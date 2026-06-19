const { getThreshold } = require('./configStore');

// Security rationale: the engine is deliberately deterministic and explainable;
// a bank SOC must justify challenges without exposing raw scoring to customers.
function normalizeFingerprint(value) {
  return String(value || 'unknown-fingerprint').trim();
}

function normalizeNetwork(value) {
  return String(value || 'unknown-network').trim();
}

function buildReplayEvents(riskReasons, decision) {
  const events = ['Credentials Verified'];

  riskReasons.forEach((reason) => {
    events.push(reason.label);
  });

  if (decision === 'CHALLENGED') {
    events.push('Challenge Triggered');
    events.push('Attack Prevented');
  } else {
    events.push('Session Authorized');
  }

  return events;
}

function calculateRisk({ user, context, now = new Date() }) {
  const fingerprint = normalizeFingerprint(context.browserFingerprint);
  const network = normalizeNetwork(context.networkSignature);
  const deviceTokenTrusted = context.deviceTokenTrusted === true;
  const clientHour = Number(context.clientHour);
  const loginHour = Number.isFinite(clientHour) && clientHour >= 0 && clientHour <= 23
    ? Math.round(clientHour)
    : now.getHours();
  const incognito = context.incognito === true || context.incognito === 'true';
  const loginDuration = Math.max(Number(context.loginDuration || 0), 0);
  const riskReasons = [];

  const knownDevice = deviceTokenTrusted || user.trustedDevices.includes(fingerprint);
  const knownNetwork = user.trustedNetworks.includes(network);

  if (!knownDevice) {
    riskReasons.push({
      label: 'Unknown Device',
      points: 35,
      detail: 'The browser fingerprint has not been observed for this account.'
    });
  }

  if (!knownNetwork) {
    riskReasons.push({
      label: 'Unknown Network',
      points: 30,
      detail: 'The network signature is outside the customer trust profile.'
    });
  }

  if (loginHour >= 1 && loginHour <= 5) {
    riskReasons.push({
      label: 'Suspicious Hour',
      points: 20,
      detail: 'The login falls inside the high-risk 1 AM to 5 AM window.'
    });
  }

  if (incognito) {
    riskReasons.push({
      label: 'Incognito Mode',
      points: 10,
      detail: 'Private browsing reduces persistence signals used for assurance.'
    });
  }

  if (loginDuration > 0 && loginDuration < 3000) {
    riskReasons.push({
      label: 'Rapid Login',
      points: 10,
      detail: 'The form was submitted faster than expected human login behavior.'
    });
  }

  const riskScore = riskReasons.reduce((total, reason) => total + reason.points, 0);
  const threshold = getThreshold();
  const status = riskScore >= threshold ? 'CHALLENGED' : 'ALLOWED';

  return {
    status,
    riskScore,
    threshold,
    riskReasons,
    replayEvents: buildReplayEvents(riskReasons, status),
    browserFingerprint: fingerprint,
    networkSignature: network,
    deviceTrusted: knownDevice,
    networkTrusted: knownNetwork,
    loginHour,
    incognito,
    loginDuration
  };
}

module.exports = {
  calculateRisk
};
