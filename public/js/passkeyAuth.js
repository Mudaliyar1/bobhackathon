(function () {
  // Security rationale: passkey login uses the platform authenticator or a synced
  // device key so customers can sign in with biometric-backed verification.
  const loginButton = document.querySelector('[data-passkey-login]');

  function toBase64Url(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';

    for (let index = 0; index < bytes.length; index += 1) {
      binary += String.fromCharCode(bytes[index]);
    }

    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
  }

  function fromBase64Url(value) {
    const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
    const padded = normalized + '==='.slice((normalized.length + 3) % 4);
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);

    for (let index = 0; index < binary.length; index += 1) {
      bytes[index] = binary.charCodeAt(index);
    }

    return bytes;
  }

  async function loginWithPasskey() {
    const usernameField = document.querySelector('[name="username"]');
    const username = usernameField ? usernameField.value.trim() : '';

    if (!username) {
      window.alert('Enter your username first.');
      return;
    }

    const optionsResponse = await fetch(`/api/passkeys/authentication/options?username=${encodeURIComponent(username)}`, {
      credentials: 'same-origin'
    });

    if (!optionsResponse.ok) {
      const error = await optionsResponse.json().catch(() => ({}));
      window.alert(error.error || 'No passkey is enrolled for this account.');
      return;
    }

    const options = await optionsResponse.json();
    const assertion = await navigator.credentials.get({
      publicKey: {
        ...options,
        challenge: fromBase64Url(options.challenge),
        allowCredentials: (options.allowCredentials || []).map((credential) => ({
          ...credential,
          id: fromBase64Url(credential.id)
        }))
      }
    });

    const response = assertion.response;
    const verificationResponse = await fetch('/api/passkeys/authentication/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({
        id: assertion.id,
        rawId: toBase64Url(assertion.rawId),
        type: assertion.type,
        response: {
          clientDataJSON: toBase64Url(response.clientDataJSON),
          authenticatorData: toBase64Url(response.authenticatorData),
          signature: toBase64Url(response.signature),
          userHandle: response.userHandle ? toBase64Url(response.userHandle) : null
        },
        username
      })
    });

    const verification = await verificationResponse.json();
    if (!verificationResponse.ok || !verification.verified) {
      window.alert(verification.error || 'Passkey login failed.');
      return;
    }

    window.location.assign(verification.redirect || '/portal');
  }

  if (loginButton) {
    loginButton.addEventListener('click', function () {
      loginWithPasskey().catch((error) => {
        window.alert(error.message || 'Passkey login failed.');
      });
    });
  }
})();
