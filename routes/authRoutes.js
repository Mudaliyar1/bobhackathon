const express = require('express');
const authController = require('../controllers/authController');

const router = express.Router();

// Security rationale: all identity, challenge, and SOC routes stay inside one
// Express app so session creation and challenge decisions share the same boundary.
router.get('/', authController.renderLogin);
router.post('/login', authController.handleLogin);
router.get('/challenge', authController.renderChallenge);
router.get('/portal', authController.renderPortal);
router.get('/admin', authController.renderAdmin);
router.get('/api/admin/dashboard', authController.dashboardApi);
router.post('/api/admin/threshold', authController.updateThreshold);
router.post('/logout', authController.logout);

module.exports = router;
