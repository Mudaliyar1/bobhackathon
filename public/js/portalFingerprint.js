(function () {
  // Security rationale: after login, the customer can enroll the current device
  // fingerprint so repeat logins from the same browser or mobile device are trusted.
  const enrollButton = document.querySelector('[data-enroll-fingerprint]');
  const fingerprintStatus = document.querySelector('[data-fingerprint-status]');
  const fingerprintState = document.querySelector('[data-fingerprint-enrolled-state]');
  const currentFingerprintLabel = document.querySelector('[data-current-fingerprint]');
  const portalConfig = window.__trustpulsePortal || {};

  function collectFingerprint() {
    const parts = [
      navigator.userAgent,
      navigator.language,
      screen.width,
      screen.height,
      screen.colorDepth,
      navigator.platform || 'platform-unknown',
      navigator.hardwareConcurrency || 'cpu-unknown',
      navigator.deviceMemory || 'memory-unknown',
      navigator.maxTouchPoints || 0,
      window.devicePixelRatio || 1,
      screen.orientation ? screen.orientation.type : 'orientation-unknown'
    ];

    let hash = 0;
    const source = parts.join('|');

    for (let index = 0; index < source.length; index += 1) {
      hash = (hash << 5) - hash + source.charCodeAt(index);
      hash |= 0;
    }

    return `browser-${Math.abs(hash)}`;
  }

  async function enrollFingerprint() {
    const fingerprint = collectFingerprint();

    try {
      const response = await fetch('/api/device/enroll', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        credentials: 'same-origin',
        body: JSON.stringify({
          fingerprint,
          userAgent: navigator.userAgent,
          language: navigator.language,
          timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || 'timezone-unknown',
          platform: navigator.platform || 'platform-unknown',
          screenWidth: screen.width,
          screenHeight: screen.height,
          clientHour: new Date().getHours()
        })
      });

      if (!response.ok) {
        throw new Error('Enrollment failed');
      }

      if (fingerprintStatus) {
        fingerprintStatus.textContent = 'This device is enrolled';
        fingerprintStatus.className = 'align-self-center small text-success';
      }

      if (fingerprintState) {
        fingerprintState.textContent = 'Enrolled';
        fingerprintState.className = 'mt-2 text-success';
      }

      if (currentFingerprintLabel) {
        currentFingerprintLabel.textContent = fingerprint;
      }

      portalConfig.currentFingerprint = fingerprint;
      portalConfig.fingerprintEnrolled = true;
    } catch (error) {
      if (fingerprintStatus) {
        fingerprintStatus.textContent = 'Enrollment failed, try again';
        fingerprintStatus.className = 'align-self-center small text-danger';
      }
    }
  }

  if (enrollButton) {
    enrollButton.addEventListener('click', enrollFingerprint);
  }

  if (currentFingerprintLabel && portalConfig.currentFingerprint) {
    currentFingerprintLabel.textContent = portalConfig.currentFingerprint;
  }
})();