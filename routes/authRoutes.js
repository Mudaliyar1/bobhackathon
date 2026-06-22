const express = require('express');
const authController = require('../controllers/authController');

const router = express.Router();

// Security rationale: all identity, challenge, and SOC routes stay inside one
// Express app so session creation and challenge decisions share the same boundary.
router.get('/', authController.renderLogin);
router.post('/login', authController.handleLogin);
router.get('/api/passkeys/authentication/options', authController.generatePasskeyAuthenticationOptions);
router.post('/api/passkeys/authentication/verify', authController.verifyPasskeyAuthentication);
router.get('/challenge', authController.renderChallenge);
router.post('/challenge/verify', authController.verifyChallenge);
router.get('/portal', authController.renderPortal);
router.get('/admin', authController.renderAdmin);
router.get('/api/passkeys/registration/options', authController.generatePasskeyRegistrationOptions);
router.post('/api/passkeys/registration/verify', authController.verifyPasskeyRegistration);
router.post('/api/device/enroll', authController.enrollFingerprint);
router.get('/api/session/status', authController.sessionStatus);
router.get('/api/admin/dashboard', authController.dashboardApi);
router.post('/api/admin/threshold', authController.updateThreshold);
router.post('/api/recovery/generate', authController.generateRecoveryCodes);
router.post('/recovery-login', authController.loginWithRecoveryCode);
router.post('/api/qr/generate', authController.generateQR);
router.get('/api/qr/status', authController.pollQRStatus);
router.post('/api/qr/approve', authController.approveQR);
router.post('/logout', authController.logout);

module.exports = router;
