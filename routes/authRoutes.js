// routes/authRoutes.js
const express = require('express');
const router = express.Router();
const { registerUser, loginUser, getProfile } = require('../controllers/authController');
const verifyToken = require('../middleware/verifyToken');
const { registerValidationRules, loginValidationRules, validate } = require('../middleware/validators');

// POST /api/auth/register
router.post('/register', registerValidationRules, validate, registerUser);

// POST /api/auth/login
router.post('/login', loginValidationRules, validate, loginUser);

// GET /api/auth/profile
router.get('/profile', verifyToken, getProfile);

module.exports = router;