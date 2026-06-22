(function () {
  // Security rationale: the collector models browser-side context that attackers
  // change during ATO attempts, then submits it before any session is authorized.
  const startedAt = Date.now();
  const fingerprintInput = document.querySelector('[name="fingerprint"]');
  const networkInput = document.querySelector('[name="networkScope"]');
  const clientHourInput = document.querySelector('[name="clientHour"]');
  const loginStartInput = document.querySelector('[name="loginStartTime"]');
  const incognitoInput = document.querySelector('[name="incognito"]');
  const durationInput = document.querySelector('[name="loginDuration"]');
  const screenWidthInput = document.querySelector('[name="screenWidth"]');
  const screenHeightInput = document.querySelector('[name="screenHeight"]');
  const userAgentInput = document.querySelector('[name="userAgent"]');
  const languageInput = document.querySelector('[name="language"]');
  const timezoneInput = document.querySelector('[name="timezone"]');
  const platformInput = document.querySelector('[name="platform"]');
  const localHourInput = document.querySelector('[name="localHour"]');
  const mobileFingerprintEnabledInput = document.querySelector('[data-mobile-fingerprint-enabled]');
  const loginForm = document.querySelector('[data-login-form]');
  const usernameInput = document.querySelector('[name="username"]');
  const passwordInput = document.querySelector('[name="password"]');
  const previewDevice = document.querySelector('[data-preview-device]');
  const previewNetwork = document.querySelector('[data-preview-network]');
  const previewMode = document.querySelector('[data-preview-mode]');

  function isMobileDevice() {
    return window.matchMedia('(pointer: coarse)').matches || navigator.maxTouchPoints > 1 || /Android|iPhone|iPad|iPod/i.test(navigator.userAgent);
  }

  function loadMobileFingerprintPreference() {
    if (!mobileFingerprintEnabledInput) {
      return;
    }

    try {
      const storedValue = localStorage.getItem('trustpulse.mobileFingerprintEnabled');
      if (storedValue === 'true') {
        mobileFingerprintEnabledInput.checked = true;
      } else if (storedValue === 'false') {
        mobileFingerprintEnabledInput.checked = false;
      } else {
        mobileFingerprintEnabledInput.checked = isMobileDevice();
      }
    } catch (error) {
      mobileFingerprintEnabledInput.checked = isMobileDevice();
    }
  }

  function saveMobileFingerprintPreference() {
    if (!mobileFingerprintEnabledInput) {
      return;
    }

    try {
      localStorage.setItem('trustpulse.mobileFingerprintEnabled', String(mobileFingerprintEnabledInput.checked));
    } catch (error) {
      // Ignore storage errors in restricted browsing modes.
    }
  }

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

  function mobileFingerprint() {
    const mobileSignals = [
      navigator.userAgent,
      navigator.language,
      navigator.platform || 'platform-unknown',
      screen.width,
      screen.height,
      window.devicePixelRatio || 1,
      navigator.maxTouchPoints || 0,
      navigator.hardwareConcurrency || 'cpu-unknown',
      navigator.deviceMemory || 'memory-unknown',
      screen.orientation ? screen.orientation.type : 'orientation-unknown'
    ];

    let hash = 0;
    const source = mobileSignals.join('|');

    for (let index = 0; index < source.length; index += 1) {
      hash = (hash << 5) - hash + source.charCodeAt(index);
      hash |= 0;
    }

    return `mobile-${Math.abs(hash)}`;
  }

  function collectBrowserContext() {
    const browserTimeZone = Intl.DateTimeFormat().resolvedOptions().timeZone || 'timezone-unknown';
    const localHour = new Date().getHours();

    return {
      width: screen.width,
      height: screen.height,
      userAgent: navigator.userAgent,
      language: navigator.language,
      timezone: browserTimeZone,
      platform: navigator.platform || 'platform-unknown',
      hour: localHour
    };
  }

  async function applyContext() {
    if (!fingerprintInput || !networkInput || !incognitoInput) return;

    const detectedIncognito = await detectIncognito();
    const browserContext = collectBrowserContext();

    if (loginStartInput) {
      loginStartInput.value = String(startedAt);
    }

    if (screenWidthInput) screenWidthInput.value = String(browserContext.width);
    if (screenHeightInput) screenHeightInput.value = String(browserContext.height);
    if (userAgentInput) userAgentInput.value = browserContext.userAgent;
    if (languageInput) languageInput.value = browserContext.language;
    if (timezoneInput) timezoneInput.value = browserContext.timezone;
    if (platformInput) platformInput.value = browserContext.platform;
    if (localHourInput) localHourInput.value = String(browserContext.hour);

    const useMobileFingerprint = Boolean(mobileFingerprintEnabledInput && mobileFingerprintEnabledInput.checked && isMobileDevice());
    fingerprintInput.value = useMobileFingerprint ? mobileFingerprint() : localFingerprint();
    networkInput.value = `browser-network-${Math.abs(hashContext(`${browserContext.userAgent}|${browserContext.platform}|${browserContext.timezone}`))}`;
    if (clientHourInput) clientHourInput.value = String(browserContext.hour);
    incognitoInput.value = detectedIncognito ? 'true' : 'false';
    updatePreview(useMobileFingerprint ? 'Mobile fingerprint' : 'Collected', 'Derived', detectedIncognito ? 'Private Browser' : 'Standard Browser');
  }

  function hashContext(source) {
    let hash = 0;

    for (let index = 0; index < source.length; index += 1) {
      hash = (hash << 5) - hash + source.charCodeAt(index);
      hash |= 0;
    }

    return hash;
  }

  function updatePreview(device, network, mode) {
    if (previewDevice) previewDevice.textContent = device;
    if (previewNetwork) previewNetwork.textContent = network;
    if (previewMode) previewMode.textContent = mode;
  }

  if (loginForm) {
    loginForm.addEventListener('submit', function () {
      saveMobileFingerprintPreference();
      durationInput.value = String(Date.now() - startedAt);
    });
  }

  if (mobileFingerprintEnabledInput) {
    mobileFingerprintEnabledInput.addEventListener('change', function () {
      saveMobileFingerprintPreference();
      applyContext();
    });
  }

  loadMobileFingerprintPreference();

  applyContext();

  window.__trustpulseCollectContext = function() {
    const browserContext = collectBrowserContext();
    
    return {
      clientHour: String(browserContext.hour),
      screenWidth: String(browserContext.width),
      screenHeight: String(browserContext.height),
      userAgent: browserContext.userAgent,
      language: browserContext.language,
      timezone: browserContext.timezone,
      platform: browserContext.platform
    };
  };
})();
