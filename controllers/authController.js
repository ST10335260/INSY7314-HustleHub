/**
 * File: controllers/authController.js
 * Description: Handles user authentication business logic, including secure input validation,
 * duplicate verification, and cryptographic password hashing via bcrypt.
 * 
 * References:
 * - Bcrypt Library Documentation: https://www.npmjs.com/package/bcrypt
 */

const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();
const users = require('../models/User');

/**
 * Controller method to register a new user account.
 */
const registerUser = async (req, res, next) => {
    try {
        const { username, email, password, role } = req.body;

        // Validates that all mandatory fields have been provided in the request body
        if (!username || !email || !password || !role) {
            return res.status(400).json({ 
                error: "Validation Error", 
                message: "All fields are required (username, email, password, role)." 
            });
        }

        // Checks the in-memory data store for existing user email conflicts
        const existingUser = users.find(user => user.email === email);
        if (existingUser) {
            return res.status(409).json({ 
                error: "Conflict", 
                message: "User with this email already exists." 
            });
        }

        // Cryptographically hashes the user password using bcrypt with a salt factor of 10
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // Constructs the new user record object
        const newUser = {
            id: users.length + 1,
            username,
            email,
            password: hashedPassword, // Stores the secure hash; plain-text passwords are strictly avoided
            role 
        };

        // Persists the new user record to the in-memory data model array
        users.push(newUser);

        // Returns a successful creation response omitting sensitive password data
        return res.status(201).json({
            status: "success",
            message: "User registered successfully",
            data: {
                id: newUser.id,
                username: newUser.username,
                email: newUser.email,
                role: newUser.role
            }
        });

    } catch (error) {
        // Delegates unhandled execution errors to the global error-handling middleware
        next(error);
    }
};

/**
 * Controller method to authenticate an existing user and issue a JSON Web Token.
 */
const loginUser = async (req, res, next) => {
    try {
        const { email, password } = req.body;

        // Validates that all mandatory fields have been provided in the request body
        if (!email || !password) {
            return res.status(400).json({
                error: "Validation Error",
                message: "Email and password are required."
            });
        }

        // Locates the user record matching the supplied email address
        const user = users.find(user => user.email === email);
        if (!user) {
            return res.status(401).json({
                error: "Unauthorized",
                message: "Invalid email or password."
            });
        }

        // Compares the supplied password against the stored bcrypt hash
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({
                error: "Unauthorized",
                message: "Invalid email or password."
            });
        }

        // Signs a JWT containing the user's id and role, expiring after 1 hour
        const token = jwt.sign(
            { id: user.id, role: user.role },
            process.env.JWT_SECRET || 'hustlehub_dev_secret',
            { expiresIn: '1h' }
        );

        // Returns the signed token along with basic non-sensitive user information
        return res.status(200).json({
            status: "success",
            message: "Login successful",
            data: {
                token,
                user: {
                    id: user.id,
                    username: user.username,
                    email: user.email,
                    role: user.role
                }
            }
        });

    } catch (error) {
        // Delegates unhandled execution errors to the global error-handling middleware
        next(error);
    }
};

/**
 * Controller method to retrieve the authenticated user's own profile information.
 * Requires a valid JWT to have already been verified by the verifyToken middleware.
 */
const getProfile = (req, res, next) => {
    try {
        // The verifyToken middleware attaches the decoded token payload to req.user
        const user = users.find(user => user.id === req.user.id);

        if (!user) {
            return res.status(404).json({
                error: "Not Found",
                message: "User associated with this token no longer exists."
            });
        }

        return res.status(200).json({
            status: "success",
            data: {
                id: user.id,
                username: user.username,
                email: user.email,
                role: user.role
            }
        });

    } catch (error) {
        next(error);
    }
};

module.exports = {
    registerUser,
    loginUser,
    getProfile
};