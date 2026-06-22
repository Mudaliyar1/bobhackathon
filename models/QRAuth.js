const mongoose = require('mongoose');
const crypto = require('crypto');

const qrAuthSchema = new mongoose.Schema(
  {
    token: {
      type: String,
      default: () => crypto.randomBytes(32).toString('hex'),
      unique: true,
      index: true
    },
    status: {
      type: String,
      enum: ['PENDING', 'APPROVED'],
      default: 'PENDING'
    },
    user_id: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      default: null
    },
    expiresAt: {
      type: Date,
      default: () => new Date(Date.now() + 5 * 60 * 1000), // Expires in 5 minutes
      index: { expires: '5m' }
    }
  },
  { timestamps: true }
);

module.exports = mongoose.model('QRAuth', qrAuthSchema);
