const jwt = require('jsonwebtoken');
const BlacklistedToken = require('../models/blacklistedToken');
const { generateAccessToken } = require('../helpers/token');
require('dotenv').config();

function parseCookies(cookieHeader = '') {
    return cookieHeader.split(';').map(c => c.trim()).filter(Boolean).reduce((acc, cur) => {
        const [k, ...v] = cur.split('=');
        acc[k] = decodeURIComponent(v.join('='));
        return acc;
    }, {});
}

const authMiddleware = async (req, res, next) => {
    let token = req.header('Authorization')?.replace(/^Bearer\s+/i, '');

    if (!token) {
        token = req.cookies?.access_token || req.cookies?.token || req.cookies?.jwt;
    }

    if (!token && req.headers.cookie) {
        const cookies = parseCookies(req.headers.cookie);
        token = cookies.access_token || cookies.token || cookies.jwt;
    }

    if (!token) return res.status(401).json({ error: 'Auth Middleware, No token provided, authorization denied !' });

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const tokenHash = generateAccessToken(token);
        const blacklisted = await BlacklistedToken.findOne({ token: tokenHash }).lean();
        if (blacklisted) return res.status(401).json({ error: 'Token has been revoked' });

        req.user = decoded;
        next();
    } catch (error) {
        res.status(401).json({ error: 'Auth Middleware Token is not valid' });
    }
};

module.exports = authMiddleware;

