/**
 * File: middleware/validators.js
 * Description: Defines express-validator rule chains for the register and login
 * endpoints, plus a shared handler that returns any validation failures in a
 * consistent, safe error format. Inputs are trimmed and escaped/normalised to
 * reduce the risk of injection and cross-site scripting (XSS) via user input.
 *
 * References:
 * - express-validator Documentation: https://express-validator.github.io/docs/
 */

const { body, validationResult } = require('express-validator');

// Validation & sanitisation rules for POST /api/auth/register
const registerValidationRules = [
    body('username')
        .trim()
        .notEmpty().withMessage('Username is required.')
        .isLength({ min: 3, max: 30 }).withMessage('Username must be between 3 and 30 characters.')
        .escape(),
    body('email')
        .trim()
        .notEmpty().withMessage('Email is required.')
        .isEmail().withMessage('A valid email address is required.')
        .normalizeEmail(),
    body('password')
        .notEmpty().withMessage('Password is required.')
        .isLength({ min: 8 }).withMessage('Password must be at least 8 characters long.')
        .matches(/[A-Z]/).withMessage('Password must contain at least one uppercase letter.')
        .matches(/[0-9]/).withMessage('Password must contain at least one number.'),
    body('role')
        .trim()
        .notEmpty().withMessage('Role is required.')
        .escape()
];

// Validation & sanitisation rules for POST /api/auth/login
const loginValidationRules = [
    body('email')
        .trim()
        .notEmpty().withMessage('Email is required.')
        .isEmail().withMessage('A valid email address is required.')
        .normalizeEmail(),
    body('password')
        .notEmpty().withMessage('Password is required.')
];

// Shared handler: inspects validation results and short-circuits with a
// consistent, user-friendly 400 response if any rule failed
const validate = (req, res, next) => {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
        return res.status(400).json({
            error: "Validation Error",
            message: "Invalid input data.",
            details: errors.array().map(e => ({ field: e.path, message: e.msg }))
        });
    }

    next();
};

module.exports = {
    registerValidationRules,
    loginValidationRules,
    validate
};
