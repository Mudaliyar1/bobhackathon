const bcrypt = require('bcryptjs');
const User = require('../models/User');
const LoginLog = require('../models/LoginLog');
const { calculateRisk, getThreshold, setThreshold } = require('../middleware/riskEngine');

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

async function seedDemoUsers() {
  const count = await User.countDocuments();
  if (count > 0) return;

  const customerPassword = await bcrypt.hash('bobsecure123', 12);
  const adminPassword = await bcrypt.hash('adminsecure123', 12);

  await User.create([
    {
      username: 'trusted',
      email: 'trusted.customer@bankofbaroda.com',
      password: customerPassword,
      trustedDevices: ['trusted-demo-device'],
      trustedNetworks: ['trusted-bank-network'],
      role: 'customer'
    },
    {
      username: 'admin',
      email: 'soc.admin@bankofbaroda.com',
      password: adminPassword,
      trustedDevices: ['trusted-demo-device'],
      trustedNetworks: ['trusted-bank-network'],
      role: 'admin'
    }
  ]);
}

function renderLogin(req, res) {
  res.render('login', {
    error: req.query.error || null,
    demo: {
      trusted: 'trusted / bobsecure123',
      admin: 'admin / adminsecure123'
    }
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

  const riskContext = calculateRisk({
    user,
    context: {
      browserFingerprint: req.body.browserFingerprint,
      networkSignature: req.body.networkSignature,
      incognito: req.body.incognito,
      loginDuration: req.body.loginDuration
    }
  });

  const log = await LoginLog.create({
    user_id: user._id,
    status: riskContext.status,
    ipAddress: getClientIp(req),
    browserFingerprint: riskContext.browserFingerprint,
    loginHour: riskContext.loginHour,
    incognito: riskContext.incognito,
    loginDuration: riskContext.loginDuration,
    riskScore: riskContext.riskScore,
    riskReasons: riskContext.riskReasons,
    replayEvents: riskContext.replayEvents
  });

  if (riskContext.status === 'CHALLENGED') {
    req.session.pendingChallenge = {
      userId: user._id.toString(),
      logId: log._id.toString()
    };
    return res.redirect('/challenge');
  }

  req.session.user = {
    id: user._id.toString(),
    username: user.username,
    email: user.email,
    role: user.role
  };

  return res.redirect(user.role === 'admin' ? '/admin' : '/portal');
}

async function renderChallenge(req, res) {
  if (!req.session.pendingChallenge) {
    return res.redirect('/');
  }

  const log = await LoginLog.findById(req.session.pendingChallenge.logId).populate('user_id');
  if (!log) {
    return res.redirect('/');
  }

  return res.render('challenge', { log, threshold: getThreshold(), formatTime });
}

function renderPortal(req, res) {
  if (!req.session.user) {
    return res.redirect('/');
  }

  res.render('portal', { user: req.session.user });
}

async function renderAdmin(req, res) {
  if (!req.session.user || req.session.user.role !== 'admin') {
    return res.redirect('/');
  }

  const data = await getDashboardData();
  res.render('admin', { data, user: req.session.user, formatTime });
}

async function getDashboardData() {
  const [totalAttempts, successfulSessions, challengesTriggered, logs] = await Promise.all([
    LoginLog.countDocuments(),
    LoginLog.countDocuments({ status: 'ALLOWED' }),
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
    threatsPrevented: challengesTriggered,
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
  renderPortal,
  renderAdmin,
  dashboardApi,
  updateThreshold,
  logout
};
