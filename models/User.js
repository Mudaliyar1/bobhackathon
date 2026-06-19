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
    trustedNetworks: {
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
