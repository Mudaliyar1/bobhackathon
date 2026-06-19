require('dotenv').config();

const path = require('path');
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const helmet = require('helmet');
const { applyDnsServers, connectDB } = require('./config/db');
const authRoutes = require('./routes/authRoutes');
const { seedDemoUsers } = require('./controllers/authController');

const app = express();
const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/ato_shield';

applyDnsServers();

// Security rationale: EJS renders the banking and SOC surfaces server-side,
// preventing a split frontend/backend session model during the demo.
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Security rationale: Helmet locks browser capabilities while explicitly
// allowing only Bootstrap and Chart.js CDN assets required by the brief.
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", 'https://cdn.jsdelivr.net'],
        styleSrc: ["'self'", 'https://cdn.jsdelivr.net', "'unsafe-inline'"],
        fontSrc: ["'self'", 'https://cdn.jsdelivr.net'],
        imgSrc: ["'self'", 'data:']
      }
    }
  })
);

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.use(
  session({
    name: 'trustpulse.sid',
    secret: process.env.SESSION_SECRET || 'trustpulse-hackathon-session-secret',
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
      mongoUrl: MONGO_URI,
      touchAfter: 60 * 60
    }),
    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production',
      maxAge: 1000 * 60 * 30
    }
  })
);

app.use('/', authRoutes);

app.use((req, res) => {
  res.status(404).redirect('/');
});

async function start() {
  await connectDB();
  await seedDemoUsers();

  app.listen(PORT, () => {
    console.log(`TrustPulse: ATO-Shield running at http://localhost:${PORT}`);
  });
}

start();
