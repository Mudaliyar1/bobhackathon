(function () {
  // Security rationale: authenticated pages re-check session validity in the background
  // so a second login from a private/incognito context can revoke the current session.
  const heartbeatIntervalMs = 500;
  let isRedirecting = false;
  let lastCheckAt = 0;
  let inFlight = false;

  function redirectToLogin() {
    if (isRedirecting) {
      return;
    }

    isRedirecting = true;
    window.location.replace('/?error=Your session was signed out because a newer trusted sign-in was detected');
  }

  function checkSession() {
    const now = Date.now();

    if (inFlight || now - lastCheckAt < 250) {
      return;
    }

    inFlight = true;
    lastCheckAt = now;

    fetch('/api/session/status', {
      credentials: 'same-origin',
      cache: 'no-store'
    })
      .then((response) => {
        if (!response.ok) {
          redirectToLogin();
        }
      })
      .catch(() => {
        redirectToLogin();
      })
      .finally(() => {
        inFlight = false;
      });
  }

  checkSession();
  setInterval(checkSession, heartbeatIntervalMs);

  function bindActiveSignals() {
    const signals = ['focus', 'visibilitychange', 'mousemove', 'keydown', 'touchstart', 'scroll', 'click'];

    signals.forEach((eventName) => {
      window.addEventListener(eventName, checkSession, { passive: true });
    });
  }

  document.addEventListener('visibilitychange', checkSession, { passive: true });
  bindActiveSignals();
})();