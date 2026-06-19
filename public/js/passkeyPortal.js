(function () {
  // Security rationale: passkey enrollment binds the current browser or mobile
  // device to the account so future sign-ins can use biometric-backed login.
  const enrollButton = document.querySelector('[data-enroll-passkey]');

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

  async function enrollPasskey() {
    const optionsResponse = await fetch('/api/passkeys/registration/options', {
      credentials: 'same-origin'
    });

    if (!optionsResponse.ok) {
      const error = await optionsResponse.json().catch(() => ({}));
      window.alert(error.error || 'Could not start passkey enrollment.');
      return;
    }

    const options = await optionsResponse.json();
    const credential = await navigator.credentials.create({
      publicKey: {
        ...options,
        challenge: fromBase64Url(options.challenge),
        user: {
          ...options.user,
          id: fromBase64Url(options.user.id)
        },
        excludeCredentials: (options.excludeCredentials || []).map((item) => ({
          ...item,
          id: fromBase64Url(item.id)
        }))
      }
    });

    const attestation = credential.response;
    const verificationResponse = await fetch('/api/passkeys/registration/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({
        id: credential.id,
        rawId: toBase64Url(credential.rawId),
        type: credential.type,
        response: {
          clientDataJSON: toBase64Url(attestation.clientDataJSON),
          attestationObject: toBase64Url(attestation.attestationObject),
          transports: credential.response.getTransports ? credential.response.getTransports() : []
        }
      })
    });

    const verification = await verificationResponse.json();
    if (!verificationResponse.ok || !verification.verified) {
      window.alert(verification.error || 'Passkey enrollment failed.');
      return;
    }

    window.location.reload();
  }

  if (enrollButton) {
    enrollButton.addEventListener('click', function () {
      enrollPasskey().catch((error) => {
        window.alert(error.message || 'Passkey enrollment failed.');
      });
    });
  }
})();
