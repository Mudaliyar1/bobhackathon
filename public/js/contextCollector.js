(function () {
  // Security rationale: the collector models browser-side context that attackers
  // change during ATO attempts, then submits it before any session is authorized.
  const startedAt = Date.now();
  const modeSelect = document.querySelector('[data-demo-mode]');
  const fingerprintInput = document.querySelector('[name="browserFingerprint"]');
  const networkInput = document.querySelector('[name="networkSignature"]');
  const incognitoInput = document.querySelector('[name="incognito"]');
  const durationInput = document.querySelector('[name="loginDuration"]');
  const loginForm = document.querySelector('[data-login-form]');
  const usernameInput = document.querySelector('[name="username"]');
  const passwordInput = document.querySelector('[name="password"]');
  const scenarioButtons = document.querySelectorAll('[data-scenario]');
  const adminButton = document.querySelector('[data-fill-admin]');
  const previewDevice = document.querySelector('[data-preview-device]');
  const previewNetwork = document.querySelector('[data-preview-network]');
  const previewMode = document.querySelector('[data-preview-mode]');

  async function detectIncognito() {
    if (!navigator.storage || !navigator.storage.estimate) {
      return false;
    }

    try {
      const estimate = await navigator.storage.estimate();
      return estimate.quota && estimate.quota < 120000000;
    } catch (error) {
      return false;
    }
  }

  function localFingerprint() {
    const parts = [
      navigator.userAgent,
      navigator.language,
      screen.width,
      screen.height,
      screen.colorDepth,
      new Date().getTimezoneOffset(),
      navigator.hardwareConcurrency || 'cpu-unknown'
    ];

    let hash = 0;
    const source = parts.join('|');
    for (let index = 0; index < source.length; index += 1) {
      hash = (hash << 5) - hash + source.charCodeAt(index);
      hash |= 0;
    }

    return `browser-${Math.abs(hash)}`;
  }

  async function applyContext() {
    if (!fingerprintInput || !networkInput || !incognitoInput) return;

    const mode = modeSelect ? modeSelect.value : 'trusted';
    const detectedIncognito = await detectIncognito();

    if (mode === 'attacker') {
      fingerprintInput.value = `${localFingerprint()}-untrusted`;
      networkInput.value = `external-network-${Math.floor(Math.random() * 9999)}`;
      incognitoInput.value = 'true';
      updatePreview('Unknown', 'External', 'ATO Attacker');
      return;
    }

    fingerprintInput.value = 'trusted-demo-device';
    networkInput.value = 'trusted-bank-network';
    incognitoInput.value = detectedIncognito ? 'true' : 'false';
    updatePreview('Known', 'Trusted', detectedIncognito ? 'Private Browser' : 'Trusted');
  }

  function updatePreview(device, network, mode) {
    if (previewDevice) previewDevice.textContent = device;
    if (previewNetwork) previewNetwork.textContent = network;
    if (previewMode) previewMode.textContent = mode;
  }

  function selectScenario(mode, options) {
    const settings = options || {};
    if (modeSelect) {
      modeSelect.value = mode;
    }

    if (!settings.preserveCredentials && usernameInput && passwordInput) {
      usernameInput.value = 'trusted';
      passwordInput.value = 'bobsecure123';
    }

    scenarioButtons.forEach((button) => {
      button.classList.toggle('active', button.dataset.scenario === mode);
    });

    applyContext();
  }

  if (modeSelect) {
    modeSelect.addEventListener('change', function () {
      selectScenario(modeSelect.value);
    });
  }

  scenarioButtons.forEach((button) => {
    button.addEventListener('click', function () {
      selectScenario(button.dataset.scenario);
    });
  });

  if (adminButton) {
    adminButton.addEventListener('click', function () {
      if (usernameInput && passwordInput) {
        usernameInput.value = 'admin';
        passwordInput.value = 'adminsecure123';
      }
      selectScenario('trusted', { preserveCredentials: true });
    });
  }

  if (loginForm) {
    loginForm.addEventListener('submit', function () {
      durationInput.value = String(Date.now() - startedAt);
    });
  }

  applyContext();
})();
