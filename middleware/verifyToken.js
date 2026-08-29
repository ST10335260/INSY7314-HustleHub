/**
 * File: middleware/verifyToken.js
 * Description: Middleware that validates the JSON Web Token supplied on protected
 * requests. Confirms the token is present, correctly signed, and not expired before
 * allowing the request to proceed, attaching the decoded payload to req.user.
 *
 * References:
 * - jsonwebtoken Library Documentation: https://www.npmjs.com/package/jsonwebtoken
 */

const jwt = require('jsonwebtoken');

const verifyToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];

    // Rejects the request immediately if no Bearer token was supplied
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({
            error: "Unauthorized",
            message: "No token provided. Access denied."
        });
    }

    const token = authHeader.split(' ')[1];

    jwt.verify(token, process.env.JWT_SECRET || 'hustlehub_dev_secret', (err, decoded) => {
        if (err) {
            // Distinguishes an expired token from any other malformed/invalid token
            if (err.name === 'TokenExpiredError') {
                return res.status(401).json({
                    error: "Unauthorized",
                    message: "Token has expired. Please log in again."
                });
            }

            return res.status(403).json({
                error: "Forbidden",
                message: "Invalid token. Access denied."
            });
        }

        // Attaches the decoded token payload (id, role) to the request for downstream use
        req.user = decoded;
        next();
    });
};

module.exports = verifyToken;
