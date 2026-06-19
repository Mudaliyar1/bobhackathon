const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const User = require('../models/User');
const LoginLog = require('../models/LoginLog');
const { calculateRisk } = require('../middleware/riskEngine');
const { getThreshold, setThreshold } = require('../middleware/configStore');
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse
} = require('@simplewebauthn/server');
const { isoUint8Array } = require('@simplewebauthn/server/helpers');

const RP_NAME = process.env.RP_NAME || 'TrustPulse: ATO-Shield';
const RP_ID = process.env.RP_ID || 'localhost';
const RP_ORIGIN = process.env.RP_ORIGIN || 'http://localhost:3000';

// Security rationale: client IP is captured as supporting telemetry, but the
// core ATO decision is driven by device and network trust after password success.
function getClientIp(req) {
  const forwardedFor = req.headers['x-forwarded-for'];
  if (forwardedFor) {
    return forwardedFor.split(',')[0].trim();
  }

  return req.socket.remoteAddress || req.ip || '127.0.0.1';
}

function formatTime(date) {
  return new Intl.DateTimeFormat('en-IN', {
    hour: '2-digit',
    minute: '2-digit',
    hour12: true,
    timeZone: 'Asia/Kolkata'
  }).format(date);
}

function normalizeIpAddress(ipAddress) {
  const raw = String(ipAddress || '').trim();

  if (!raw) {
    return '127.0.0.1';
  }

  if (raw.startsWith('::ffff:')) {
    return raw.replace('::ffff:', '');
  }

  if (raw === '::1') {
    return '127.0.0.1';
  }

  return raw;
}

function getCookieValue(req, name) {
  const cookieHeader = String(req.headers.cookie || '');
  const prefix = `${name}=`;

  for (const part of cookieHeader.split(';')) {
    const cookie = part.trim();
    if (cookie.startsWith(prefix)) {
      return decodeURIComponent(cookie.slice(prefix.length));
    }
  }

  return null;
}

function hashToken(token) {
  return crypto.createHash('sha256').update(String(token || '')).digest('hex');
}

function issueTrustToken(res) {
  const token = crypto.randomBytes(32).toString('hex');

  res.cookie('trustpulse_device', token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 1000 * 60 * 60 * 24 * 30
  });

  return token;
}

function toBase64Url(value) {
  return Buffer.from(value).toString('base64url');
}

function fromBase64Url(value) {
  return Buffer.from(String(value), 'base64url');
}

function ensureWebAuthnUserID(user) {
  if (user.webauthnUserID) {
    return user.webauthnUserID;
  }

  return crypto.randomBytes(16).toString('base64url');
}

function shouldAllowOnboardingGrace(user, fingerprintMetadata, deviceTokenTrusted, fingerprintTrusted) {
  const hasTrustedBaseline = (user.trustedDevices || []).length > 0 || (user.enrolledFingerprints || []).length > 0 || (user.passkeys || []).length > 0;

  if (!hasTrustedBaseline) {
    return true;
  }

  if (deviceTokenTrusted || fingerprintTrusted) {
    return true;
  }

  return Boolean(fingerprintMetadata.browserFingerprint && fingerprintMetadata.userAgent);
}

function listPasskeys(user) {
  return Array.isArray(user.passkeys) ? user.passkeys : [];
}

function deriveNetworkSignature(req) {
  const forwardedFor = req.headers['x-forwarded-for'];
  const primaryIp = normalizeIpAddress(
    forwardedFor ? forwardedFor.split(',')[0].trim() : req.socket.remoteAddress || req.ip
  );

  const ipv4Match = primaryIp.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (ipv4Match) {
    return `net-${ipv4Match[1]}.${ipv4Match[2]}.${ipv4Match[3]}`;
  }

  if (primaryIp === '127.0.0.1') {
    return 'net-127.0.0';
  }

  const ipv6Match = primaryIp.match(/^([0-9a-fA-F]{1,4}):([0-9a-fA-F]{1,4}):([0-9a-fA-F]{1,4}):([0-9a-fA-F]{1,4})/);
  if (ipv6Match) {
    return `net-${ipv6Match[1]}:${ipv6Match[2]}:${ipv6Match[3]}:${ipv6Match[4]}`;
  }

  return `net-${primaryIp.toLowerCase()}`;
}

async function assertActiveSession(req, res) {
  if (!req.session.user) {
    return false;
  }

  const user = await User.findById(req.session.user.id).select('sessionVersion');
  const currentVersion = Number(user ? user.sessionVersion : 0);
  const sessionVersion = Number(req.session.sessionVersion || 0);

  if (!user || sessionVersion !== currentVersion) {
    req.session.destroy(() => {});
    res.redirect('/?error=Your session was signed out because a newer trusted sign-in was detected');
    return false;
  }

  return true;
}

function generateStepUpCode() {
  return String(crypto.randomInt(100000, 999999));
}

function normalizeTrustList(values) {
  return Array.from(new Set((values || []).map((value) => String(value || '').trim()).filter(Boolean))).slice(-10);
}

function collectFingerprintMetadata(req) {
  return {
    browserFingerprint: String(req.body.fingerprint || req.body.browserFingerprint || '').trim(),
    screenWidth: Number(req.body.screenWidth) || 0,
    screenHeight: Number(req.body.screenHeight) || 0,
    userAgent: String(req.body.userAgent || '').slice(0, 240),
    language: String(req.body.language || '').slice(0, 64),
    timezone: String(req.body.timezone || '').slice(0, 96),
    platform: String(req.body.platform || '').slice(0, 80),
    clientHour: Number(req.body.clientHour)
  };
}

function isFingerprintEnrolled(user, fingerprint) {
  return Boolean(fingerprint && Array.isArray(user.enrolledFingerprints) && user.enrolledFingerprints.includes(fingerprint));
}

async function enrollTrustedContext(user, trustedContext) {
  const trustedDevices = normalizeTrustList([...user.trustedDevices, trustedContext.browserFingerprint]);
  const trustedNetworks = normalizeTrustList([...user.trustedNetworks, trustedContext.networkSignature]);
  const trustedDeviceTokens = normalizeTrustList([...user.trustedDeviceTokens, trustedContext.deviceTokenHash]);
  const enrolledFingerprints = normalizeTrustList([...user.enrolledFingerprints, trustedContext.browserFingerprint]);

  await User.updateOne(
    { _id: user._id },
    {
      $set: {
        trustedDevices,
        trustedNetworks,
        trustedDeviceTokens,
        enrolledFingerprints
      }
    }
  );
}

async function bumpSessionVersion(user) {
  const nextSessionVersion = Number(user.sessionVersion || 0) + 1;

  await User.updateOne(
    { _id: user._id },
    {
      $set: {
        sessionVersion: nextSessionVersion
      }
    }
  );

  user.sessionVersion = nextSessionVersion;
  return nextSessionVersion;
}

async function seedDemoUsers() {
  const customerPassword = await bcrypt.hash('Bank@123', 12);
  const adminPassword = await bcrypt.hash('adminsecure123', 12);

  await User.updateOne(
    { username: 'vijay' },
    {
      $set: {
        email: 'vijay@example.com',
        password: customerPassword,
        trustedDevices: [],
        enrolledFingerprints: [],
        trustedNetworks: ['net-127.0.0'],
        trustedDeviceTokens: [],
        sessionVersion: 0,
        passkeys: [],
        role: 'customer'
      }
    },
    { upsert: true }
  );

  await User.updateOne(
    { username: 'admin' },
    {
      $set: {
        email: 'soc.admin@bankofbaroda.com',
        password: adminPassword,
        trustedDevices: [],
        enrolledFingerprints: [],
        trustedNetworks: ['net-127.0.0'],
        trustedDeviceTokens: [],
        sessionVersion: 0,
        passkeys: [],
        role: 'admin'
      }
    },
    { upsert: true }
  );
}

function renderLogin(req, res) {
  res.render('login', {
    error: req.query.error || null
  });
}

async function handleLogin(req, res) {
  const { username, password } = req.body;
  const user = await User.findOne({ username: String(username || '').toLowerCase().trim() });

  if (!user) {
    return res.redirect('/?error=Invalid banking credentials');
  }

  const passwordValid = await bcrypt.compare(String(password || ''), user.password);
  if (!passwordValid) {
    return res.redirect('/?error=Invalid banking credentials');
  }

  const fingerprintMetadata = collectFingerprintMetadata(req);

  const existingTrustToken = getCookieValue(req, 'trustpulse_device');
  const deviceTokenHash = existingTrustToken ? hashToken(existingTrustToken) : null;
  const deviceTokenTrusted = Boolean(deviceTokenHash && user.trustedDeviceTokens.includes(deviceTokenHash));
  const fingerprintTrusted = isFingerprintEnrolled(user, fingerprintMetadata.browserFingerprint);
  const onboardingGrace = shouldAllowOnboardingGrace(user, fingerprintMetadata, deviceTokenTrusted, fingerprintTrusted);

  const riskContext = calculateRisk({
    user,
    context: {
      browserFingerprint: fingerprintMetadata.browserFingerprint,
      networkSignature: deriveNetworkSignature(req),
      deviceTokenTrusted,
      fingerprintTrusted,
      onboardingGrace,
      incognito: req.body.incognito,
      loginDuration: req.body.loginDuration || (Date.now() - Number(req.body.loginStartTime || Date.now())),
      clientHour: fingerprintMetadata.clientHour,
      screenWidth: fingerprintMetadata.screenWidth,
      screenHeight: fingerprintMetadata.screenHeight,
      userAgent: fingerprintMetadata.userAgent,
      language: fingerprintMetadata.language,
      timezone: fingerprintMetadata.timezone,
      platform: fingerprintMetadata.platform,
      localHour: req.body.localHour
    }
  });

  const log = await LoginLog.create({
    user_id: user._id,
    status: riskContext.status,
    sessionAuthorized: riskContext.status === 'ALLOWED',
    stepUpVerified: false,
    stepUpMethod: 'none',
    ipAddress: getClientIp(req),
    browserFingerprint: riskContext.browserFingerprint,
    loginHour: riskContext.loginHour,
    incognito: riskContext.incognito,
    loginDuration: riskContext.loginDuration,
    screenWidth: Number(req.body.screenWidth) || undefined,
    screenHeight: Number(req.body.screenHeight) || undefined,
    userAgent: String(req.body.userAgent || '').slice(0, 240),
    language: String(req.body.language || '').slice(0, 64),
    timezone: String(req.body.timezone || '').slice(0, 96),
    platform: String(req.body.platform || '').slice(0, 80),
    riskScore: riskContext.riskScore,
    deviceTrusted: riskContext.deviceTrusted,
    networkTrusted: riskContext.networkTrusted,
    riskReasons: riskContext.riskReasons,
    replayEvents: riskContext.replayEvents
  });

  if (riskContext.status === 'CHALLENGED') {
    const challengeToken = existingTrustToken || issueTrustToken(res);
    req.session.pendingChallenge = {
      userId: user._id.toString(),
      logId: log._id.toString(),
      challengeCode: generateStepUpCode(),
      trustedContext: {
        browserFingerprint: riskContext.browserFingerprint,
        networkSignature: riskContext.networkSignature,
        deviceTokenHash: hashToken(challengeToken)
      }
    };
    return res.redirect('/challenge');
  }

  const nextSessionVersion = await bumpSessionVersion(user);

  await enrollTrustedContext(user, {
    browserFingerprint: riskContext.browserFingerprint,
    networkSignature: riskContext.networkSignature,
    deviceTokenHash: deviceTokenHash || hashToken(issueTrustToken(res))
  });

  req.session.user = {
    id: user._id.toString(),
    username: user.username,
    email: user.email,
    role: user.role
  };

  req.session.sessionVersion = nextSessionVersion;
  req.session.currentFingerprint = riskContext.browserFingerprint;
  req.session.onboardingGrace = onboardingGrace;

  return res.redirect(user.role === 'admin' ? '/admin' : '/portal');
}

async function generatePasskeyRegistrationOptions(req, res) {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const isActive = await assertActiveSession(req, res);
  if (!isActive) {
    return;
  }

  const user = await User.findById(req.session.user.id);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  const webauthnUserID = ensureWebAuthnUserID(user);
  const currentOptions = await generateRegistrationOptions({
    rpName: RP_NAME,
    rpID: RP_ID,
    userID: isoUint8Array.fromUTF8String(webauthnUserID),
    userName: user.username,
    attestationType: 'none',
    excludeCredentials: listPasskeys(user).map((passkey) => ({
      id: fromBase64Url(passkey.id),
      transports: passkey.transports
    })),
    authenticatorSelection: {
      residentKey: 'preferred',
      userVerification: 'required'
    }
  });

  req.session.passkeyRegistration = currentOptions;
  req.session.webauthnUserID = webauthnUserID;

  return res.json(currentOptions);
}

async function verifyPasskeyRegistration(req, res) {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const isActive = await assertActiveSession(req, res);
  if (!isActive) {
    return;
  }

  const user = await User.findById(req.session.user.id);
  const currentOptions = req.session.passkeyRegistration;
  if (!user || !currentOptions) {
    return res.status(400).json({ error: 'Missing registration state' });
  }

  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response: req.body,
      expectedChallenge: currentOptions.challenge,
      expectedOrigin: RP_ORIGIN,
      expectedRPID: RP_ID
    });
  } catch (error) {
    return res.status(400).json({ error: error.message });
  }

  if (!verification.verified) {
    return res.status(400).json({ error: 'Passkey registration failed' });
  }

  const { registrationInfo } = verification;
  const updatedPasskeys = [
    ...listPasskeys(user),
    {
      id: registrationInfo.credential.id,
      publicKey: Buffer.from(registrationInfo.credential.publicKey),
      counter: registrationInfo.credential.counter,
      transports: registrationInfo.credential.transports || [],
      deviceType: registrationInfo.credentialDeviceType,
      backedUp: registrationInfo.credentialBackedUp
    }
  ];

  await User.updateOne(
    { _id: user._id },
    {
      $set: {
        webauthnUserID: req.session.webauthnUserID || user.webauthnUserID,
        passkeys: updatedPasskeys
      }
    }
  );

  req.session.passkeyRegistration = null;

  return res.json({ verified: true });
}

async function generatePasskeyAuthenticationOptions(req, res) {
  const { username } = req.query;
  if (!username) {
    return res.status(400).json({ error: 'Username is required' });
  }

  const user = await User.findOne({ username: String(username).toLowerCase().trim() });
  if (!user || !listPasskeys(user).length) {
    return res.status(404).json({ error: 'No passkey enrolled for this user' });
  }

  const currentOptions = await generateAuthenticationOptions({
    rpID: RP_ID,
    allowCredentials: listPasskeys(user).map((passkey) => ({
      id: fromBase64Url(passkey.id),
      transports: passkey.transports
    })),
    userVerification: 'required'
  });

  req.session.passkeyAuthentication = {
    username: user.username,
    challenge: currentOptions.challenge
  };

  return res.json(currentOptions);
}

async function verifyPasskeyAuthentication(req, res) {
  const { username } = req.body;
  const pending = req.session.passkeyAuthentication;

  if (!username || !pending || pending.username !== String(username).toLowerCase().trim()) {
    return res.status(400).json({ error: 'Missing authentication state' });
  }

  const user = await User.findOne({ username: pending.username });
  if (!user || !listPasskeys(user).length) {
    return res.status(404).json({ error: 'No passkey enrolled for this user' });
  }

  const credential = listPasskeys(user).find((passkey) => passkey.id === req.body.id);
  if (!credential) {
    return res.status(404).json({ error: 'Passkey credential not found' });
  }

  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response: req.body,
      expectedChallenge: pending.challenge,
      expectedOrigin: RP_ORIGIN,
      expectedRPID: RP_ID,
      credential: {
        id: credential.id,
        publicKey: credential.publicKey instanceof Buffer ? new Uint8Array(credential.publicKey) : credential.publicKey,
        counter: credential.counter,
        transports: credential.transports
      }
    });
  } catch (error) {
    return res.status(400).json({ error: error.message });
  }

  if (!verification.verified) {
    return res.status(400).json({ error: 'Passkey authentication failed' });
  }

  const updatedPasskeys = listPasskeys(user).map((passkey) => (
    passkey.id === credential.id ? { ...passkey, counter: verification.authenticationInfo.newCounter } : passkey
  ));

  await User.updateOne(
    { _id: user._id },
    {
      $set: {
        passkeys: updatedPasskeys
      }
    }
  );

  await bumpSessionVersion(user);

  req.session.user = {
    id: user._id.toString(),
    username: user.username,
    email: user.email,
    role: user.role
  };
  req.session.sessionVersion = Number(user.sessionVersion || 0);
  req.session.passkeyAuthentication = null;
  req.session.currentFingerprint = credential.id;
  req.session.onboardingGrace = false;

  return res.json({ verified: true, redirect: user.role === 'admin' ? '/admin' : '/portal' });
}

async function renderPortal(req, res) {
  if (!req.session.user) {
    return res.redirect('/');
  }

  const isActive = await assertActiveSession(req, res);
  if (!isActive) {
    return;
  }

  const user = await User.findById(req.session.user.id);
  if (!user) {
    return res.redirect('/');
  }

  const currentFingerprint = String(req.session.currentFingerprint || '');
  const fingerprintEnrolled = isFingerprintEnrolled(user, currentFingerprint);

  return res.render('portal', {
    user: req.session.user,
    fingerprintEnrolled,
    currentFingerprint,
    passkeyCount: listPasskeys(user).length
  });
}

async function renderChallenge(req, res) {
  if (!req.session.pendingChallenge) {
    return res.redirect('/');
  }

  const log = await LoginLog.findById(req.session.pendingChallenge.logId).populate('user_id');
  if (!log) {
    return res.redirect('/');
  }

  return res.render('challenge', {
    log,
    threshold: getThreshold(),
    formatTime,
    error: req.query.error || null
  });
}

async function verifyChallenge(req, res) {
  const pendingChallenge = req.session.pendingChallenge;

  if (!pendingChallenge) {
    return res.redirect('/');
  }

  const submittedCode = String(req.body.verificationCode || '').trim();
  if (submittedCode !== pendingChallenge.challengeCode) {
    return res.redirect('/challenge?error=Verification code did not match');
  }

  const user = await User.findById(pendingChallenge.userId);
  const log = await LoginLog.findById(pendingChallenge.logId);

  if (!user || !log) {
    req.session.pendingChallenge = null;
    return res.redirect('/');
  }

  await enrollTrustedContext(user, pendingChallenge.trustedContext);

  log.sessionAuthorized = true;
  log.stepUpVerified = true;
  log.stepUpMethod = 'verification-code';
  log.status = 'ALLOWED';
  log.replayEvents = [...log.replayEvents, 'Step-up Verified', 'Session Authorized'];
  await log.save();

  req.session.user = {
    id: user._id.toString(),
    username: user.username,
    email: user.email,
    role: user.role
  };

  req.session.sessionVersion = Number(user.sessionVersion || 0);

  req.session.pendingChallenge = null;

  return res.redirect(user.role === 'admin' ? '/admin' : '/portal');
}

async function sessionStatus(req, res) {
  if (!req.session.user) {
    return res.status(401).json({ active: false, reason: 'no-session' });
  }

  const user = await User.findById(req.session.user.id).select('sessionVersion');
  if (!user || Number(req.session.sessionVersion || 0) !== Number(user.sessionVersion || 0)) {
    req.session.destroy(() => {});
    return res.status(401).json({ active: false, reason: 'session-revoked' });
  }

  return res.json({ active: true });
}

async function renderAdmin(req, res) {
  if (!req.session.user || req.session.user.role !== 'admin') {
    return res.redirect('/');
  }

  const isActive = await assertActiveSession(req, res);
  if (!isActive) {
    return;
  }

  const data = await getDashboardData();
  res.render('admin', { data, user: req.session.user, formatTime });
}

async function enrollFingerprint(req, res) {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const isActive = await assertActiveSession(req, res);
  if (!isActive) {
    return;
  }

  const user = await User.findById(req.session.user.id);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  const fingerprintMetadata = collectFingerprintMetadata(req);
  if (!fingerprintMetadata.browserFingerprint) {
    return res.status(400).json({ error: 'Fingerprint missing' });
  }

  const trustedDevices = normalizeTrustList([...user.trustedDevices, fingerprintMetadata.browserFingerprint]);
  const enrolledFingerprints = normalizeTrustList([...user.enrolledFingerprints, fingerprintMetadata.browserFingerprint]);

  await User.updateOne(
    { _id: user._id },
    {
      $set: {
        trustedDevices,
        enrolledFingerprints
      }
    }
  );

  req.session.currentFingerprint = fingerprintMetadata.browserFingerprint;
  req.session.onboardingGrace = false;

  return res.json({
    ok: true,
    fingerprint: fingerprintMetadata.browserFingerprint,
    fingerprintEnrolled: true
  });
}

async function getDashboardData() {
  const [totalAttempts, successfulSessions, challengesTriggered, logs] = await Promise.all([
    LoginLog.countDocuments(),
    LoginLog.countDocuments({ sessionAuthorized: true }),
    LoginLog.countDocuments({ status: 'CHALLENGED' }),
    LoginLog.find().sort({ timestamp: -1 }).limit(20).populate('user_id', 'username email')
  ]);

  const riskBuckets = {
    low: await LoginLog.countDocuments({ riskScore: { $lt: 35 } }),
    medium: await LoginLog.countDocuments({ riskScore: { $gte: 35, $lt: getThreshold() } }),
    high: await LoginLog.countDocuments({ riskScore: { $gte: getThreshold() } })
  };

  const latestThreat = logs.find((log) => log.status === 'CHALLENGED');
  const heatLevel = challengesTriggered === 0 ? 'LOW' : challengesTriggered < 5 ? 'ELEVATED' : 'CRITICAL';

  return {
    totalAttempts,
    successfulSessions,
    challengesTriggered,
    threatsPrevented: await LoginLog.countDocuments({ status: 'CHALLENGED', sessionAuthorized: false }),
    currentThreshold: getThreshold(),
    heatLevel,
    latestThreat,
    logs,
    riskBuckets
  };
}

async function dashboardApi(req, res) {
  if (!req.session.user || req.session.user.role !== 'admin') {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const data = await getDashboardData();
  res.json(data);
}

function updateThreshold(req, res) {
  if (!req.session.user || req.session.user.role !== 'admin') {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const currentThreshold = setThreshold(req.body.threshold);
  res.json({ currentThreshold });
}

function logout(req, res) {
  req.session.destroy(() => {
    res.redirect('/');
  });
}

module.exports = {
  seedDemoUsers,
  renderLogin,
  handleLogin,
  renderChallenge,
  verifyChallenge,
  renderPortal,
  renderAdmin,
  generatePasskeyRegistrationOptions,
  verifyPasskeyRegistration,
  generatePasskeyAuthenticationOptions,
  verifyPasskeyAuthentication,
  enrollFingerprint,
  sessionStatus,
  dashboardApi,
  updateThreshold,
  logout
};
