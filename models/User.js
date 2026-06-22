const mongoose = require('mongoose');

// Security rationale: trusted device and network lists represent the customer's
// normal login baseline; ATO-Shield compares valid-password attempts against it.
const userSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      lowercase: true
    },
    email: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      lowercase: true
    },
    password: {
      type: String,
      required: true
    },
    trustedDevices: {
      type: [String],
      default: []
    },
    enrolledFingerprints: {
      type: [String],
      default: []
    },
    webauthnUserID: {
      type: String,
      unique: true,
      sparse: true,
      trim: true
    },
    trustedNetworks: {
      type: [String],
      default: []
    },
    trustedDeviceTokens: {
      type: [String],
      default: []
    },
    sessionVersion: {
      type: Number,
      default: 0
    },
    passkeys: {
      type: [
        {
          id: String,
          publicKey: Buffer,
          counter: { type: Number, default: 0 },
          transports: { type: [String], default: [] },
          deviceType: { type: String, default: 'multiDevice' },
          backedUp: { type: Boolean, default: false }
        }
      ],
      default: []
    },
    recoveryCodes: {
      type: [String],
      default: []
    },
    role: {
      type: String,
      enum: ['customer', 'admin'],
      default: 'customer'
    }
  },
  { timestamps: true }
);

module.exports = mongoose.model('User', userSchema);
