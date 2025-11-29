const express = require('express');
const router = express.Router();
const User = require('../models/user');
const AuthMiddleware = require('../middleware/auth');
const BlacklistedToken = require('../models/blacklistedToken');
const { generateAccessToken } = require('../helpers/token');

function parseCookies(cookieHeader = '') {
    return cookieHeader.split(';').map(c => c.trim()).filter(Boolean).reduce((acc, cur) => {
        const [k, ...v] = cur.split('=');
        acc[k] = decodeURIComponent(v.join('='));
        return acc;
    }, {});
}

router.get('/me', AuthMiddleware, async (req, res) => {
    try {
        let token = req.header('Authorization')?.replace(/^Bearer\s+/i, '');
        if (!token) {
            token = req.cookies?.access_token || req.cookies?.token || req.cookies?.jwt;
        }
        if (!token && req.headers.cookie) {
            const cookies = parseCookies(req.headers.cookie);
            token = cookies.access_token || cookies.token || cookies.jwt;
        }

        if (!token) {
            return res.status(401).json({ error: 'No access token provided' });
        }

        const tokenHash = generateAccessToken(token);
        const blacklisted = await BlacklistedToken.findOne({ token: tokenHash }).lean();
        if (blacklisted) {
            return res.status(401).json({ error: 'Token has been revoked' });
        }

        const user = await User.findById(req.user.id).select('-password');
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json(user);
    } catch (error) {
        res.status(500).json({ error: 'Server Error' });
    }
});

module.exports = router;