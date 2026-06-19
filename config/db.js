const mongoose = require('mongoose');
const dns = require('dns');

function applyDnsServers() {
  const dnsServers = (process.env.DNS_SERVERS || '8.8.8.8,1.1.1.1')
    .split(',')
    .map((server) => server.trim())
    .filter(Boolean);

  if (dnsServers.length) {
    // Security rationale: Atlas SRV lookups must resolve reliably before the
    // risk engine can persist login decisions; explicit resolvers avoid local
    // DNS failures such as querySrv ECONNREFUSED.
    dns.setServers(dnsServers);
  }
}

async function connectDB() {
  // Security rationale: centralizing the database connection keeps audit data and
  // session state on one trusted MongoDB boundary for the hackathon deployment.
  applyDnsServers();
  const mongoUri = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/ato_shield';

  try {
    await mongoose.connect(mongoUri);
    console.log(`MongoDB connected for TrustPulse: ${mongoose.connection.host}`);
  } catch (error) {
    console.error('MongoDB connection failed:', error.message);
    process.exit(1);
  }
}

module.exports = {
  applyDnsServers,
  connectDB
};
