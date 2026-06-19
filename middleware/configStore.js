const DEFAULT_THRESHOLD = 65;

let globalThreshold = DEFAULT_THRESHOLD;

function getThreshold() {
  // Security rationale: SOC-controlled thresholding lets the bank tune friction
  // without changing the ATO risk rules or redeploying the app during an incident.
  return globalThreshold;
}

function setThreshold(value) {
  const parsed = Number(value);

  if (!Number.isFinite(parsed)) {
    return globalThreshold;
  }

  globalThreshold = Math.min(Math.max(Math.round(parsed), 0), 105);
  return globalThreshold;
}

module.exports = {
  DEFAULT_THRESHOLD,
  getThreshold,
  setThreshold
};
