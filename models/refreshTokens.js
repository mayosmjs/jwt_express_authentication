const mongoose = require('mongoose');

const refreshTokenSchema = new mongoose.Schema({
    token: { type: String, required: true, unique: true },
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    jti: { type: String, required: true, index: true },
    createdAt: { type: Date, default: Date.now }, 
    expiresAt: { type: Date, required: true, index: true },
    revokedAt: { type: Date, default: null },
    replacedByToken: { type: String, default: null },
    ipAddress: { type: String, default: null },
    userAgent: { type: String, default: null }   
});
module.exports = mongoose.model('RefreshToken', refreshTokenSchema);