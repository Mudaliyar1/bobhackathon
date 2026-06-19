const mongoose = require('mongoose');

// Security rationale: every post-password decision is stored with context,
// reasons, and replay events so SOC analysts can explain why a session was blocked.
const loginLogSchema = new mongoose.Schema(
  {
    user_id: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true
    },
    timestamp: {
      type: Date,
      default: Date.now,
      index: true
    },
    status: {
      type: String,
      enum: ['ALLOWED', 'CHALLENGED'],
      required: true,
      index: true
    },
    ipAddress: {
      type: String,
      required: true
    },
    browserFingerprint: {
      type: String,
      required: true
    },
    loginHour: {
      type: Number,
      min: 0,
      max: 23,
      required: true
    },
    incognito: {
      type: Boolean,
      default: false
    },
    loginDuration: {
      type: Number,
      required: true
    },
    riskScore: {
      type: Number,
      required: true
    },
    riskReasons: {
      type: [
        {
          label: String,
          points: Number,
          detail: String
        }
      ],
      default: []
    },
    replayEvents: {
      type: [String],
      default: []
    }
  },
  { timestamps: true }
);

module.exports = mongoose.model('LoginLog', loginLogSchema);
