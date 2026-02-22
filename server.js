const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const GitHubStrategy = require('passport-github2').Strategy;
const MicrosoftStrategy = require('passport-microsoft').Strategy;
const nodemailer = require('nodemailer');

// Polyfill fetch for Node.js < 18
const fetch = globalThis.fetch || require('node-fetch');

const app = express();
const PORT = process.env.PORT || 3001;

// Secret for JWT-like token signing - MUST be consistent across restarts
const SECRET_KEY = process.env.SECRET_KEY || 'trustelix-audit-platform-secret-key-2024';

// OAuth Configuration
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const GITHUB_CLIENT_ID = process.env.GITHUB_CLIENT_ID;
const GITHUB_CLIENT_SECRET = process.env.GITHUB_CLIENT_SECRET;
const MICROSOFT_CLIENT_ID = process.env.MICROSOFT_CLIENT_ID;
const MICROSOFT_CLIENT_SECRET = process.env.MICROSOFT_CLIENT_SECRET;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

// Email Configuration (for password reset)
const SMTP_HOST = process.env.SMTP_HOST || 'smtp.gmail.com';
const SMTP_PORT = parseInt(process.env.SMTP_PORT) || 587;
const SMTP_USER = process.env.SMTP_USER;
const SMTP_PASS = process.env.SMTP_PASS;
const EMAIL_FROM = process.env.EMAIL_FROM || SMTP_USER || 'noreply@trustelix.com';

// Create email transporter
let emailTransporter = null;
if (SMTP_USER && SMTP_PASS) {
  try {
    emailTransporter = nodemailer.createTransport({
      host: SMTP_HOST,
      port: SMTP_PORT,
      secure: SMTP_PORT === 465,
      auth: {
        user: SMTP_USER,
        pass: SMTP_PASS
      }
    });
    // Verify connection
    emailTransporter.verify((error, success) => {
      if (error) {
        console.log('⚠ Email service error:', error.message);
        emailTransporter = null;
      } else {
        console.log('✓ Email service configured and verified');
      }
    });
  } catch (e) {
    console.log('⚠ Email setup failed:', e.message);
  }
} else {
  console.log('○ Email service not configured (set SMTP_USER and SMTP_PASS)');
}

// Admin Configuration
const OAUTH_ADMIN_EMAIL = 'newreal8y@gmail.com';
// Password Admin: Can login with username/password
const PASSWORD_ADMIN_EMAIL = 'admin@trustelix.local';
const PASSWORD_ADMIN_USERNAME = 'admin';
const PASSWORD_ADMIN_PASSWORD = '@dm1n1!';

app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Session configuration for OAuth
app.use(session({
  secret: SECRET_KEY,
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: process.env.NODE_ENV === 'production',
    maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
  }
}));

// Initialize Passport
app.use(passport.initialize());
app.use(passport.session());

// Passport serialization
passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  const user = db.users.find(u => u.id === id);
  done(null, user || null);
});

// ============================================================
// JSON FILE-BASED DATABASE (Persistent Storage)
// ============================================================
const DATA_DIR = path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'database.json');

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

function loadDB() {
  try {
    if (fs.existsSync(DB_FILE)) {
      const data = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
      // Ensure new fields exist
      data.passwordResetTokens = data.passwordResetTokens || {};
      data.analytics = data.analytics || { pageViews: [], actions: [], sessions: [] };
      data.errorLogs = data.errorLogs || [];
      data.feedback = data.feedback || [];
      return data;
    }
  } catch (e) {
    console.error('Error loading database:', e);
  }
  return { 
    users: [], 
    companies: [], 
    assessments: {}, 
    history: [],
    userCompanyAccess: {}, // Maps userId -> [companyIds]
    passwordResetTokens: {}, // Maps token -> { userId, expires }
    analytics: { pageViews: [], actions: [], sessions: [] },
    errorLogs: [],
    feedback: []
  };
}

function saveDB(data) {
  fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
}

let db = loadDB();

// Initialize admin users
function initializeAdmin() {
  let updated = false;
  
  // Create password-based admin account
  const passwordAdmin = db.users.find(u => u.email === PASSWORD_ADMIN_EMAIL || u.username === PASSWORD_ADMIN_USERNAME);
  if (!passwordAdmin) {
    const adminUser = {
      id: crypto.randomUUID(),
      email: PASSWORD_ADMIN_EMAIL,
      username: PASSWORD_ADMIN_USERNAME,
      password: hashPassword(PASSWORD_ADMIN_PASSWORD),
      name: 'System Administrator',
      role: 'admin',
      createdAt: new Date().toISOString()
    };
    db.users.push(adminUser);
    db.userCompanyAccess[adminUser.id] = [];
    updated = true;
    console.log('✓ Password admin initialized (admin / @dm1n1!)');
  } else if (!passwordAdmin.role) {
    passwordAdmin.role = 'admin';
    updated = true;
  }
  
  // Pre-register OAuth admin (will be linked when they sign in via Google)
  const oauthAdmin = db.users.find(u => u.email === OAUTH_ADMIN_EMAIL);
  if (!oauthAdmin) {
    const adminUser = {
      id: crypto.randomUUID(),
      email: OAUTH_ADMIN_EMAIL,
      name: 'OAuth Administrator',
      role: 'admin',
      oauthPending: true, // Will be completed when they sign in via Google
      createdAt: new Date().toISOString()
    };
    db.users.push(adminUser);
    db.userCompanyAccess[adminUser.id] = [];
    updated = true;
    console.log('✓ OAuth admin pre-registered (newreal8y@gmail.com - use Google Sign-In)');
  } else if (!oauthAdmin.role) {
    oauthAdmin.role = 'admin';
    updated = true;
  }
  
  if (updated) {
    saveDB(db);
  }
}

// Helper to check if user is admin
function isAdmin(user) {
  if (!user) return false;
  return user.role === 'admin' || user.email === OAUTH_ADMIN_EMAIL || user.email === PASSWORD_ADMIN_EMAIL;
}

// Admin middleware
function adminMiddleware(req, res, next) {
  if (!isAdmin(req.user)) {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
}

// Log analytics event
function logAnalytics(userId, action, details = {}) {
  db.analytics.actions.push({
    userId,
    action,
    details,
    timestamp: new Date().toISOString()
  });
  // Keep only last 10000 entries
  if (db.analytics.actions.length > 10000) {
    db.analytics.actions = db.analytics.actions.slice(-10000);
  }
  saveDB(db);
}

// Log error
function logError(error, context = {}) {
  db.errorLogs.push({
    id: crypto.randomUUID(),
    message: error.message || error,
    stack: error.stack,
    context,
    timestamp: new Date().toISOString()
  });
  // Keep only last 1000 errors
  if (db.errorLogs.length > 1000) {
    db.errorLogs = db.errorLogs.slice(-1000);
  }
  saveDB(db);
}

// ============================================================
// OAUTH STRATEGIES CONFIGURATION
// ============================================================
function findOrCreateOAuthUser(profile, provider) {
  // Check if user exists with this OAuth provider
  let user = db.users.find(u => u.oauthProvider === provider && u.oauthId === profile.id);
  
  if (!user) {
    // Check if email exists (link accounts)
    const email = profile.emails?.[0]?.value || `${profile.id}@${provider}.oauth`;
    user = db.users.find(u => u.email === email);
    
    if (user) {
      // Link OAuth to existing account (preserves admin role)
      user.oauthProvider = provider;
      user.oauthId = profile.id;
      user.avatar = profile.photos?.[0]?.value || user.avatar;
      user.name = user.name || profile.displayName || profile.username;
      delete user.oauthPending; // Remove pending flag if it was pre-registered
      saveDB(db);
      console.log(`✓ OAuth linked to existing account: ${email} (role: ${user.role || 'user'})`);
    } else {
      // Create new user
      user = {
        id: crypto.randomUUID(),
        email: email,
        name: profile.displayName || profile.username || email.split('@')[0],
        avatar: profile.photos?.[0]?.value || null,
        oauthProvider: provider,
        oauthId: profile.id,
        createdAt: new Date().toISOString()
      };
      db.users.push(user);
      db.userCompanyAccess[user.id] = [];
      saveDB(db);
    }
  }
  
  return user;
}

// Google OAuth Strategy
if (GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET) {
  passport.use(new GoogleStrategy({
    clientID: GOOGLE_CLIENT_ID,
    clientSecret: GOOGLE_CLIENT_SECRET,
    callbackURL: `${BASE_URL}/auth/google/callback`
  }, (accessToken, refreshToken, profile, done) => {
    try {
      const user = findOrCreateOAuthUser(profile, 'google');
      done(null, user);
    } catch (error) {
      done(error, null);
    }
  }));
  console.log('✓ Google OAuth configured');
}

// GitHub OAuth Strategy
if (GITHUB_CLIENT_ID && GITHUB_CLIENT_SECRET) {
  passport.use(new GitHubStrategy({
    clientID: GITHUB_CLIENT_ID,
    clientSecret: GITHUB_CLIENT_SECRET,
    callbackURL: `${BASE_URL}/auth/github/callback`
  }, (accessToken, refreshToken, profile, done) => {
    try {
      const user = findOrCreateOAuthUser(profile, 'github');
      done(null, user);
    } catch (error) {
      done(error, null);
    }
  }));
  console.log('✓ GitHub OAuth configured');
}

// Microsoft/Outlook OAuth Strategy
if (MICROSOFT_CLIENT_ID && MICROSOFT_CLIENT_SECRET) {
  passport.use(new MicrosoftStrategy({
    clientID: MICROSOFT_CLIENT_ID,
    clientSecret: MICROSOFT_CLIENT_SECRET,
    callbackURL: `${BASE_URL}/auth/microsoft/callback`,
    scope: ['user.read']
  }, (accessToken, refreshToken, profile, done) => {
    try {
      const user = findOrCreateOAuthUser(profile, 'microsoft');
      done(null, user);
    } catch (error) {
      done(error, null);
    }
  }));
  console.log('✓ Microsoft/Outlook OAuth configured');
}

// ============================================================
// AUTHENTICATION MIDDLEWARE
// ============================================================
function hashPassword(password) {
  return crypto.createHash('sha256').update(password + SECRET_KEY).digest('hex');
}

function generateToken(userId) {
  const payload = { userId, exp: Date.now() + (7 * 24 * 60 * 60 * 1000) }; // 7 days
  const data = Buffer.from(JSON.stringify(payload)).toString('base64');
  const signature = crypto.createHmac('sha256', SECRET_KEY).update(data).digest('hex');
  return `${data}.${signature}`;
}

function verifyToken(token) {
  if (!token) return null;
  try {
    const [data, signature] = token.split('.');
    const expectedSig = crypto.createHmac('sha256', SECRET_KEY).update(data).digest('hex');
    if (signature !== expectedSig) return null;
    
    const payload = JSON.parse(Buffer.from(data, 'base64').toString());
    if (payload.exp < Date.now()) return null;
    
    return payload.userId;
  } catch (e) {
    return null;
  }
}

function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  
  const token = authHeader.substring(7);
  const userId = verifyToken(token);
  
  if (!userId) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
  
  const user = db.users.find(u => u.id === userId);
  if (!user) {
    return res.status(401).json({ error: 'User not found' });
  }
  
  req.userId = userId;
  req.user = user;
  next();
}

// Initialize admin user now that hashPassword is available
initializeAdmin();

// ============================================================
// CONTROL EQUIVALENCE MAPPINGS (30 Groups - Expanded for NIST 800-171 & CMMC)
// ============================================================
const EQUIVALENCE_GROUPS = [
  {
    name: 'Security Policy',
    controls: [
      { framework: 'iso27001', controlId: '5.1' },
      { framework: 'nist', controlId: 'GV.PO-01' },
      { framework: 'soc2', controlId: 'CC5.3' },
      { framework: 'hipaa', controlId: '164.308.a.1.i' },
      { framework: 'pci', controlId: '12.1' },
      { framework: 'gdpr', controlId: 'Art.24' },
      { framework: 'nist800171', controlId: '3.1.1' },
      { framework: 'cmmc', controlId: 'AC.L2-3.1.1' }
    ]
  },
  {
    name: 'Risk Assessment',
    controls: [
      { framework: 'iso27001', controlId: '5.7' },
      { framework: 'nist', controlId: 'ID.RA-01' },
      { framework: 'soc2', controlId: 'CC3.2' },
      { framework: 'hipaa', controlId: '164.308.a.1.ii.A' },
      { framework: 'pci', controlId: '12.2' },
      { framework: 'gdpr', controlId: 'Art.35' },
      { framework: 'nist800171', controlId: '3.11.1' },
      { framework: 'cmmc', controlId: 'RA.L2-3.11.1' }
    ]
  },
  {
    name: 'Access Control',
    controls: [
      { framework: 'iso27001', controlId: '5.15' },
      { framework: 'nist', controlId: 'PR.AA-05' },
      { framework: 'soc2', controlId: 'CC6.1' },
      { framework: 'hipaa', controlId: '164.312.a.1' },
      { framework: 'pci', controlId: '7.1' },
      { framework: 'gdpr', controlId: 'Art.32' },
      { framework: 'nist800171', controlId: '3.1.2' },
      { framework: 'cmmc', controlId: 'AC.L2-3.1.2' }
    ]
  },
  {
    name: 'Identity Management',
    controls: [
      { framework: 'iso27001', controlId: '5.16' },
      { framework: 'nist', controlId: 'PR.AA-01' },
      { framework: 'soc2', controlId: 'CC6.2' },
      { framework: 'hipaa', controlId: '164.312.a.2.i' },
      { framework: 'pci', controlId: '8.1' },
      { framework: 'nist800171', controlId: '3.5.1' },
      { framework: 'cmmc', controlId: 'IA.L2-3.5.1' }
    ]
  },
  {
    name: 'Authentication',
    controls: [
      { framework: 'iso27001', controlId: '8.5' },
      { framework: 'nist', controlId: 'PR.AA-03' },
      { framework: 'soc2', controlId: 'CC6.1' },
      { framework: 'hipaa', controlId: '164.312.d' },
      { framework: 'pci', controlId: '8.3' },
      { framework: 'nist800171', controlId: '3.5.3' },
      { framework: 'cmmc', controlId: 'IA.L2-3.5.3' }
    ]
  },
  {
    name: 'Security Awareness Training',
    controls: [
      { framework: 'iso27001', controlId: '6.3' },
      { framework: 'nist', controlId: 'PR.AT-01' },
      { framework: 'soc2', controlId: 'CC1.4' },
      { framework: 'hipaa', controlId: '164.308.a.5' },
      { framework: 'pci', controlId: '12.6' },
      { framework: 'nist800171', controlId: '3.2.1' },
      { framework: 'cmmc', controlId: 'AT.L2-3.2.1' }
    ]
  },
  {
    name: 'Incident Response',
    controls: [
      { framework: 'iso27001', controlId: '5.24' },
      { framework: 'nist', controlId: 'RS.MA-01' },
      { framework: 'soc2', controlId: 'CC7.4' },
      { framework: 'hipaa', controlId: '164.308.a.6' },
      { framework: 'pci', controlId: '12.10' },
      { framework: 'gdpr', controlId: 'Art.33' },
      { framework: 'nist800171', controlId: '3.6.1' },
      { framework: 'cmmc', controlId: 'IR.L2-3.6.1' }
    ]
  },
  {
    name: 'Data Encryption',
    controls: [
      { framework: 'iso27001', controlId: '8.24' },
      { framework: 'nist', controlId: 'PR.DS-01' },
      { framework: 'soc2', controlId: 'CC6.7' },
      { framework: 'hipaa', controlId: '164.312.a.2.iv' },
      { framework: 'pci', controlId: '4.2' },
      { framework: 'gdpr', controlId: 'Art.32.1.a' },
      { framework: 'nist800171', controlId: '3.13.11' },
      { framework: 'cmmc', controlId: 'SC.L2-3.13.11' }
    ]
  },
  {
    name: 'Backup and Recovery',
    controls: [
      { framework: 'iso27001', controlId: '8.13' },
      { framework: 'nist', controlId: 'PR.DS-11' },
      { framework: 'soc2', controlId: 'A1.2' },
      { framework: 'hipaa', controlId: '164.308.a.7.ii.A' },
      { framework: 'pci', controlId: '10.3' },
      { framework: 'nist800171', controlId: '3.8.9' },
      { framework: 'cmmc', controlId: 'MP.L2-3.8.9' }
    ]
  },
  {
    name: 'Audit Logging',
    controls: [
      { framework: 'iso27001', controlId: '8.15' },
      { framework: 'nist', controlId: 'DE.CM-01' },
      { framework: 'soc2', controlId: 'CC7.2' },
      { framework: 'hipaa', controlId: '164.312.b' },
      { framework: 'pci', controlId: '10.1' },
      { framework: 'nist800171', controlId: '3.3.1' },
      { framework: 'cmmc', controlId: 'AU.L2-3.3.1' }
    ]
  },
  {
    name: 'Malware Protection',
    controls: [
      { framework: 'iso27001', controlId: '8.7' },
      { framework: 'nist', controlId: 'DE.CM-04' },
      { framework: 'soc2', controlId: 'CC6.6' },
      { framework: 'hipaa', controlId: '164.308.a.5.ii.B' },
      { framework: 'pci', controlId: '5.2' },
      { framework: 'nist800171', controlId: '3.14.2' },
      { framework: 'cmmc', controlId: 'SI.L2-3.14.2' }
    ]
  },
  {
    name: 'Vulnerability Management',
    controls: [
      { framework: 'iso27001', controlId: '8.8' },
      { framework: 'nist', controlId: 'ID.RA-01' },
      { framework: 'soc2', controlId: 'CC7.1' },
      { framework: 'pci', controlId: '6.3' },
      { framework: 'nist800171', controlId: '3.11.2' },
      { framework: 'cmmc', controlId: 'RA.L2-3.11.2' }
    ]
  },
  {
    name: 'Change Management',
    controls: [
      { framework: 'iso27001', controlId: '8.32' },
      { framework: 'nist', controlId: 'PR.PS-01' },
      { framework: 'soc2', controlId: 'CC8.1' },
      { framework: 'pci', controlId: '6.5' },
      { framework: 'nist800171', controlId: '3.4.3' },
      { framework: 'cmmc', controlId: 'CM.L2-3.4.3' }
    ]
  },
  {
    name: 'Physical Security',
    controls: [
      { framework: 'iso27001', controlId: '7.1' },
      { framework: 'nist', controlId: 'PR.AA-06' },
      { framework: 'soc2', controlId: 'CC6.4' },
      { framework: 'hipaa', controlId: '164.310.a.1' },
      { framework: 'pci', controlId: '9.1' },
      { framework: 'nist800171', controlId: '3.10.1' },
      { framework: 'cmmc', controlId: 'PE.L2-3.10.1' }
    ]
  },
  {
    name: 'Asset Management',
    controls: [
      { framework: 'iso27001', controlId: '5.9' },
      { framework: 'nist', controlId: 'ID.AM-01' },
      { framework: 'soc2', controlId: 'CC6.5' },
      { framework: 'pci', controlId: '2.4' },
      { framework: 'nist800171', controlId: '3.4.1' },
      { framework: 'cmmc', controlId: 'CM.L2-3.4.1' }
    ]
  },
  {
    name: 'Vendor Management',
    controls: [
      { framework: 'iso27001', controlId: '5.19' },
      { framework: 'nist', controlId: 'GV.SC-01' },
      { framework: 'soc2', controlId: 'CC9.2' },
      { framework: 'hipaa', controlId: '164.308.b.1' },
      { framework: 'pci', controlId: '12.8' },
      { framework: 'gdpr', controlId: 'Art.28' }
    ]
  },
  {
    name: 'Business Continuity',
    controls: [
      { framework: 'iso27001', controlId: '5.30' },
      { framework: 'nist', controlId: 'RC.RP-01' },
      { framework: 'soc2', controlId: 'A1.2' },
      { framework: 'hipaa', controlId: '164.308.a.7' }
    ]
  },
  {
    name: 'Data Classification',
    controls: [
      { framework: 'iso27001', controlId: '5.12' },
      { framework: 'nist', controlId: 'ID.AM-05' },
      { framework: 'soc2', controlId: 'CC6.7' },
      { framework: 'pci', controlId: '3.1' },
      { framework: 'nist800171', controlId: '3.8.1' },
      { framework: 'cmmc', controlId: 'MP.L2-3.8.1' }
    ]
  },
  {
    name: 'Privacy/Data Protection',
    controls: [
      { framework: 'iso27001', controlId: '5.34' },
      { framework: 'soc2', controlId: 'P1.1' },
      { framework: 'hipaa', controlId: '164.524' },
      { framework: 'gdpr', controlId: 'Art.5.1.a' }
    ]
  },
  {
    name: 'Network Security',
    controls: [
      { framework: 'iso27001', controlId: '8.20' },
      { framework: 'nist', controlId: 'PR.PT-04' },
      { framework: 'soc2', controlId: 'CC6.6' },
      { framework: 'hipaa', controlId: '164.312.e.1' },
      { framework: 'pci', controlId: '1.1' },
      { framework: 'nist800171', controlId: '3.13.1' },
      { framework: 'cmmc', controlId: 'SC.L2-3.13.1' }
    ]
  },
  {
    name: 'Session Management',
    controls: [
      { framework: 'iso27001', controlId: '8.6' },
      { framework: 'nist800171', controlId: '3.1.10' },
      { framework: 'cmmc', controlId: 'AC.L2-3.1.10' },
      { framework: 'pci', controlId: '8.6' }
    ]
  },
  {
    name: 'Remote Access',
    controls: [
      { framework: 'iso27001', controlId: '8.21' },
      { framework: 'nist800171', controlId: '3.1.12' },
      { framework: 'cmmc', controlId: 'AC.L2-3.1.12' },
      { framework: 'pci', controlId: '8.3' }
    ]
  },
  {
    name: 'Wireless Security',
    controls: [
      { framework: 'iso27001', controlId: '8.22' },
      { framework: 'nist800171', controlId: '3.1.16' },
      { framework: 'cmmc', controlId: 'AC.L2-3.1.16' },
      { framework: 'pci', controlId: '4.1' }
    ]
  },
  {
    name: 'Mobile Device Security',
    controls: [
      { framework: 'iso27001', controlId: '8.1' },
      { framework: 'nist800171', controlId: '3.1.18' },
      { framework: 'cmmc', controlId: 'AC.L2-3.1.18' }
    ]
  },
  {
    name: 'Configuration Management',
    controls: [
      { framework: 'iso27001', controlId: '8.9' },
      { framework: 'nist', controlId: 'PR.PS-01' },
      { framework: 'nist800171', controlId: '3.4.2' },
      { framework: 'cmmc', controlId: 'CM.L2-3.4.2' },
      { framework: 'pci', controlId: '2.2' }
    ]
  },
  {
    name: 'System Integrity',
    controls: [
      { framework: 'iso27001', controlId: '8.19' },
      { framework: 'nist', controlId: 'PR.DS-08' },
      { framework: 'nist800171', controlId: '3.14.1' },
      { framework: 'cmmc', controlId: 'SI.L2-3.14.1' }
    ]
  },
  {
    name: 'Media Protection',
    controls: [
      { framework: 'iso27001', controlId: '7.10' },
      { framework: 'nist800171', controlId: '3.8.1' },
      { framework: 'cmmc', controlId: 'MP.L2-3.8.1' },
      { framework: 'hipaa', controlId: '164.310.d.1' }
    ]
  },
  {
    name: 'Personnel Security',
    controls: [
      { framework: 'iso27001', controlId: '6.1' },
      { framework: 'nist800171', controlId: '3.9.1' },
      { framework: 'cmmc', controlId: 'PS.L2-3.9.1' }
    ]
  },
  {
    name: 'Maintenance',
    controls: [
      { framework: 'iso27001', controlId: '7.13' },
      { framework: 'nist800171', controlId: '3.7.1' },
      { framework: 'cmmc', controlId: 'MA.L2-3.7.1' }
    ]
  },
  {
    name: 'Security Assessment',
    controls: [
      { framework: 'iso27001', controlId: '5.35' },
      { framework: 'nist', controlId: 'ID.RA-05' },
      { framework: 'nist800171', controlId: '3.12.1' },
      { framework: 'cmmc', controlId: 'CA.L2-3.12.1' },
      { framework: 'soc2', controlId: 'CC4.1' }
    ]
  }
];

// Build lookup for fast control -> group mapping
const controlToGroup = new Map();
for (const group of EQUIVALENCE_GROUPS) {
  for (const ctrl of group.controls) {
    const key = `${ctrl.framework}:${ctrl.controlId}`;
    controlToGroup.set(key, group);
  }
}

function getEquivalentControls(framework, controlId) {
  const key = `${framework}:${controlId}`;
  const group = controlToGroup.get(key);
  if (!group) return [];
  return group.controls.filter(c => !(c.framework === framework && c.controlId === controlId));
}

// ============================================================
// AUTH API ROUTES
// ============================================================

// Register
app.post('/api/auth/register', (req, res) => {
  const { email, password, name } = req.body;
  
  if (!email || !password || !name) {
    return res.status(400).json({ error: 'Email, password, and name are required' });
  }
  
  if (db.users.find(u => u.email.toLowerCase() === email.toLowerCase())) {
    return res.status(400).json({ error: 'Email already registered' });
  }
  
  const user = {
    id: Date.now().toString(),
    email: email.toLowerCase(),
    password: hashPassword(password),
    name,
    createdAt: new Date().toISOString()
  };
  
  db.users.push(user);
  db.userCompanyAccess[user.id] = [];
  saveDB(db);
  
  const token = generateToken(user.id);
  res.json({ 
    token, 
    user: { id: user.id, email: user.email, name: user.name } 
  });
});

// Login
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  
  // Allow login with email OR username
  const user = db.users.find(u => 
    u.email?.toLowerCase() === email?.toLowerCase() || 
    u.username?.toLowerCase() === email?.toLowerCase()
  );
  
  if (!user || !user.password || user.password !== hashPassword(password)) {
    logAnalytics(null, 'login_failed', { email });
    return res.status(401).json({ error: 'Invalid email/username or password' });
  }
  
  // Check if this is an OAuth-only account
  if (user.oauthPending) {
    return res.status(401).json({ error: 'This account requires Google Sign-In' });
  }
  
  // Update last login
  user.lastLogin = new Date().toISOString();
  saveDB(db);
  
  logAnalytics(user.id, 'login_success', { method: 'password' });
  
  const token = generateToken(user.id);
  res.json({ 
    token, 
    user: { id: user.id, email: user.email, name: user.name, role: user.role || 'user' } 
  });
});

// Get current user
app.get('/api/auth/me', authMiddleware, (req, res) => {
  res.json({ 
    id: req.user.id, 
    email: req.user.email, 
    name: req.user.name,
    role: req.user.role || 'user',
    avatar: req.user.avatar || null,
    oauthProvider: req.user.oauthProvider || null
  });
});

// Check OAuth availability
app.get('/api/auth/oauth-config', (req, res) => {
  res.json({
    google: !!(GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET),
    github: !!(GITHUB_CLIENT_ID && GITHUB_CLIENT_SECRET),
    microsoft: !!(MICROSOFT_CLIENT_ID && MICROSOFT_CLIENT_SECRET),
    emailConfigured: !!emailTransporter
  });
});

// ============================================================
// PASSWORD RESET ROUTES
// ============================================================

// Request password reset
app.post('/api/auth/forgot-password', async (req, res) => {
  const { email } = req.body;
  
  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }
  
  const user = db.users.find(u => u.email.toLowerCase() === email.toLowerCase());
  
  // Always return success to prevent email enumeration
  if (!user) {
    return res.json({ message: 'If an account exists with that email, a reset link has been sent.' });
  }
  
  // Check if user is OAuth-only
  if (user.oauthProvider && !user.password) {
    return res.json({ message: 'If an account exists with that email, a reset link has been sent.' });
  }
  
  // Generate reset token
  const resetToken = crypto.randomBytes(32).toString('hex');
  const expires = Date.now() + (60 * 60 * 1000); // 1 hour
  
  db.passwordResetTokens[resetToken] = {
    userId: user.id,
    expires
  };
  saveDB(db);
  
  // Send email
  if (emailTransporter) {
    try {
      const resetUrl = `${BASE_URL}/?reset=${resetToken}`;
      await emailTransporter.sendMail({
        from: EMAIL_FROM,
        to: user.email,
        subject: 'TrustElix Audit Platform - Password Reset',
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <div style="background: linear-gradient(135deg, #1e3a5f 0%, #3b82f6 100%); padding: 20px; text-align: center;">
              <h1 style="color: white; margin: 0;">TrustElix Audit Platform</h1>
            </div>
            <div style="padding: 30px; background: #f9fafb;">
              <h2 style="color: #1f2937;">Password Reset Request</h2>
              <p style="color: #4b5563;">Hello ${user.name || 'User'},</p>
              <p style="color: #4b5563;">We received a request to reset your password. Click the button below to create a new password:</p>
              <div style="text-align: center; margin: 30px 0;">
                <a href="${resetUrl}" style="background: #3b82f6; color: white; padding: 12px 30px; text-decoration: none; border-radius: 8px; font-weight: bold;">Reset Password</a>
              </div>
              <p style="color: #6b7280; font-size: 14px;">This link will expire in 1 hour.</p>
              <p style="color: #6b7280; font-size: 14px;">If you didn't request this, please ignore this email.</p>
            </div>
            <div style="padding: 15px; text-align: center; color: #9ca3af; font-size: 12px;">
              © TrustElix Audit Platform
            </div>
          </div>
        `
      });
      logAnalytics(user.id, 'password_reset_requested', { email: user.email });
    } catch (error) {
      logError(error, { context: 'password_reset_email', userId: user.id });
      console.error('Failed to send reset email:', error);
    }
  } else {
    console.log('Password reset token (email not configured):', resetToken);
  }
  
  res.json({ message: 'If an account exists with that email, a reset link has been sent.' });
});

// Verify reset token
app.get('/api/auth/verify-reset-token', (req, res) => {
  const { token } = req.query;
  
  const resetData = db.passwordResetTokens[token];
  if (!resetData || resetData.expires < Date.now()) {
    return res.status(400).json({ error: 'Invalid or expired reset token' });
  }
  
  res.json({ valid: true });
});

// Reset password
app.post('/api/auth/reset-password', (req, res) => {
  const { token, password } = req.body;
  
  if (!token || !password) {
    return res.status(400).json({ error: 'Token and password are required' });
  }
  
  if (password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  }
  
  const resetData = db.passwordResetTokens[token];
  if (!resetData || resetData.expires < Date.now()) {
    return res.status(400).json({ error: 'Invalid or expired reset token' });
  }
  
  const user = db.users.find(u => u.id === resetData.userId);
  if (!user) {
    return res.status(400).json({ error: 'User not found' });
  }
  
  user.password = hashPassword(password);
  delete db.passwordResetTokens[token];
  saveDB(db);
  
  logAnalytics(user.id, 'password_reset_completed', {});
  
  res.json({ message: 'Password reset successful. You can now login with your new password.' });
});

// ============================================================
// ADMIN ROUTES
// ============================================================

// Get all users (admin only)
app.get('/api/admin/users', authMiddleware, adminMiddleware, (req, res) => {
  const users = db.users.map(u => ({
    id: u.id,
    email: u.email,
    username: u.username || null,
    name: u.name,
    role: u.role || 'user',
    oauthProvider: u.oauthProvider,
    createdAt: u.createdAt,
    lastLogin: u.lastLogin
  }));
  res.json(users);
});

// Update user role (admin only)
app.put('/api/admin/users/:userId/role', authMiddleware, adminMiddleware, (req, res) => {
  const { userId } = req.params;
  const { role } = req.body;
  
  if (!['user', 'admin'].includes(role)) {
    return res.status(400).json({ error: 'Invalid role' });
  }
  
  const user = db.users.find(u => u.id === userId);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }
  
  user.role = role;
  saveDB(db);
  
  logAnalytics(req.userId, 'admin_user_role_changed', { targetUserId: userId, newRole: role });
  
  res.json({ message: 'User role updated', user: { id: user.id, email: user.email, role: user.role } });
});

// Delete user (admin only)
app.delete('/api/admin/users/:userId', authMiddleware, adminMiddleware, (req, res) => {
  const { userId } = req.params;
  
  // Prevent self-deletion
  if (userId === req.userId) {
    return res.status(400).json({ error: 'Cannot delete your own account' });
  }
  
  const userIndex = db.users.findIndex(u => u.id === userId);
  if (userIndex === -1) {
    return res.status(404).json({ error: 'User not found' });
  }
  
  const deletedUser = db.users[userIndex];
  db.users.splice(userIndex, 1);
  delete db.userCompanyAccess[userId];
  saveDB(db);
  
  logAnalytics(req.userId, 'admin_user_deleted', { deletedUserId: userId, deletedEmail: deletedUser.email });
  
  res.json({ message: 'User deleted' });
});

// Create user (admin only)
app.post('/api/admin/users', authMiddleware, adminMiddleware, (req, res) => {
  const { email, password, name, username, role } = req.body;
  
  if (!email || !password || !name) {
    return res.status(400).json({ error: 'Email, password, and name are required' });
  }
  
  if (db.users.find(u => u.email?.toLowerCase() === email.toLowerCase())) {
    return res.status(400).json({ error: 'Email already registered' });
  }
  
  if (username && db.users.find(u => u.username?.toLowerCase() === username.toLowerCase())) {
    return res.status(400).json({ error: 'Username already taken' });
  }
  
  const user = {
    id: crypto.randomUUID(),
    email: email.toLowerCase(),
    username: username || null,
    password: hashPassword(password),
    name,
    role: role || 'user',
    createdAt: new Date().toISOString()
  };
  
  db.users.push(user);
  db.userCompanyAccess[user.id] = [];
  saveDB(db);
  
  logAnalytics(req.userId, 'admin_user_created', { newUserId: user.id, newEmail: user.email });
  
  res.json({ message: 'User created', user: { id: user.id, email: user.email, username: user.username, name: user.name, role: user.role } });
});

// Get analytics (admin only)
app.get('/api/admin/analytics', authMiddleware, adminMiddleware, (req, res) => {
  const now = Date.now();
  const day = 24 * 60 * 60 * 1000;
  const week = 7 * day;
  const month = 30 * day;
  
  // User stats
  const totalUsers = db.users.length;
  const adminUsers = db.users.filter(u => u.role === 'admin').length;
  const newUsersThisWeek = db.users.filter(u => new Date(u.createdAt).getTime() > now - week).length;
  const newUsersThisMonth = db.users.filter(u => new Date(u.createdAt).getTime() > now - month).length;
  
  // Action stats
  const actionsToday = db.analytics.actions.filter(a => new Date(a.timestamp).getTime() > now - day).length;
  const actionsThisWeek = db.analytics.actions.filter(a => new Date(a.timestamp).getTime() > now - week).length;
  
  // Popular actions
  const actionCounts = {};
  db.analytics.actions.forEach(a => {
    actionCounts[a.action] = (actionCounts[a.action] || 0) + 1;
  });
  const popularActions = Object.entries(actionCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([action, count]) => ({ action, count }));
  
  // Recent actions
  const recentActions = db.analytics.actions.slice(-50).reverse();
  
  // Company stats
  const totalCompanies = db.companies.length;
  const totalAssessments = Object.keys(db.assessments).length;
  
  res.json({
    users: {
      total: totalUsers,
      admins: adminUsers,
      newThisWeek: newUsersThisWeek,
      newThisMonth: newUsersThisMonth
    },
    activity: {
      actionsToday,
      actionsThisWeek,
      popularActions,
      recentActions
    },
    companies: {
      total: totalCompanies,
      totalAssessments
    }
  });
});

// Get error logs (admin only)
app.get('/api/admin/errors', authMiddleware, adminMiddleware, (req, res) => {
  const errors = db.errorLogs.slice(-100).reverse();
  res.json(errors);
});

// Clear error logs (admin only)
app.delete('/api/admin/errors', authMiddleware, adminMiddleware, (req, res) => {
  db.errorLogs = [];
  saveDB(db);
  res.json({ message: 'Error logs cleared' });
});

// ============================================================
// FEEDBACK ROUTES
// ============================================================

// Submit feedback
app.post('/api/feedback', authMiddleware, (req, res) => {
  const { rating, type, message } = req.body;
  
  if (!rating || rating < 1 || rating > 5) {
    return res.status(400).json({ error: 'Rating must be between 1 and 5' });
  }
  
  if (!type || !['feedback', 'bug', 'enhancement'].includes(type)) {
    return res.status(400).json({ error: 'Type must be feedback, bug, or enhancement' });
  }
  
  const feedback = {
    id: crypto.randomUUID(),
    userId: req.userId,
    userEmail: req.user.email,
    userName: req.user.name,
    rating,
    type,
    message: message || '',
    status: 'new',
    createdAt: new Date().toISOString()
  };
  
  db.feedback.push(feedback);
  saveDB(db);
  
  logAnalytics(req.userId, 'feedback_submitted', { type, rating });
  
  res.json({ message: 'Thank you for your feedback!', feedback: { id: feedback.id } });
});

// Get all feedback (admin only)
app.get('/api/admin/feedback', authMiddleware, adminMiddleware, (req, res) => {
  const feedback = db.feedback.slice().reverse();
  
  // Calculate stats
  const stats = {
    total: feedback.length,
    averageRating: feedback.length > 0 ? (feedback.reduce((sum, f) => sum + f.rating, 0) / feedback.length).toFixed(1) : 0,
    byType: {
      feedback: feedback.filter(f => f.type === 'feedback').length,
      bug: feedback.filter(f => f.type === 'bug').length,
      enhancement: feedback.filter(f => f.type === 'enhancement').length
    },
    byStatus: {
      new: feedback.filter(f => f.status === 'new').length,
      reviewed: feedback.filter(f => f.status === 'reviewed').length,
      resolved: feedback.filter(f => f.status === 'resolved').length
    }
  };
  
  res.json({ feedback, stats });
});

// Update feedback status (admin only)
app.put('/api/admin/feedback/:feedbackId', authMiddleware, adminMiddleware, (req, res) => {
  const { feedbackId } = req.params;
  const { status, adminNotes } = req.body;
  
  const feedback = db.feedback.find(f => f.id === feedbackId);
  if (!feedback) {
    return res.status(404).json({ error: 'Feedback not found' });
  }
  
  if (status) feedback.status = status;
  if (adminNotes !== undefined) feedback.adminNotes = adminNotes;
  feedback.updatedAt = new Date().toISOString();
  
  saveDB(db);
  
  res.json({ message: 'Feedback updated', feedback });
});

// ============================================================
// OAUTH ROUTES
// ============================================================

// Google OAuth
app.get('/auth/google', (req, res, next) => {
  if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) {
    return res.status(400).send('Google OAuth not configured. Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET environment variables.');
  }
  passport.authenticate('google', { scope: ['profile', 'email'] })(req, res, next);
});

app.get('/auth/google/callback', 
  passport.authenticate('google', { failureRedirect: '/?error=google_auth_failed' }),
  (req, res) => {
    // Generate token for the authenticated user
    const token = generateToken(req.user.id);
    // Redirect to frontend with token
    res.redirect(`/?token=${token}&oauth=google`);
  }
);

// GitHub OAuth
app.get('/auth/github', (req, res, next) => {
  if (!GITHUB_CLIENT_ID || !GITHUB_CLIENT_SECRET) {
    return res.status(400).send('GitHub OAuth not configured. Set GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET environment variables.');
  }
  passport.authenticate('github', { scope: ['user:email'] })(req, res, next);
});

app.get('/auth/github/callback',
  passport.authenticate('github', { failureRedirect: '/?error=github_auth_failed' }),
  (req, res) => {
    // Generate token for the authenticated user
    const token = generateToken(req.user.id);
    // Redirect to frontend with token
    res.redirect(`/?token=${token}&oauth=github`);
  }
);

// Microsoft/Outlook OAuth
app.get('/auth/microsoft', (req, res, next) => {
  if (!MICROSOFT_CLIENT_ID || !MICROSOFT_CLIENT_SECRET) {
    return res.status(400).send('Microsoft OAuth not configured. Set MICROSOFT_CLIENT_ID and MICROSOFT_CLIENT_SECRET environment variables.');
  }
  passport.authenticate('microsoft', { scope: ['user.read'] })(req, res, next);
});

app.get('/auth/microsoft/callback',
  passport.authenticate('microsoft', { failureRedirect: '/?error=microsoft_auth_failed' }),
  (req, res) => {
    // Generate token for the authenticated user
    const token = generateToken(req.user.id);
    // Redirect to frontend with token
    res.redirect(`/?token=${token}&oauth=microsoft`);
  }
);

// ============================================================
// COMPANY API ROUTES (Protected)
// ============================================================

// Get user's companies
app.get('/api/companies', authMiddleware, (req, res) => {
  const companyIds = db.userCompanyAccess[req.userId] || [];
  const companies = db.companies.filter(c => companyIds.includes(c.id));
  res.json(companies);
});

// Create a company
app.post('/api/companies', authMiddleware, (req, res) => {
  const { name, industry, size } = req.body;
  if (!name) return res.status(400).json({ error: 'Name required' });
  
  const company = {
    id: Date.now().toString(),
    name,
    industry: industry || 'Technology',
    size: size || 'Medium',
    ownerId: req.userId,
    createdAt: new Date().toISOString()
  };
  
  db.companies.push(company);
  db.assessments[company.id] = {};
  
  // Grant access to creator
  if (!db.userCompanyAccess[req.userId]) {
    db.userCompanyAccess[req.userId] = [];
  }
  db.userCompanyAccess[req.userId].push(company.id);
  
  saveDB(db);
  res.json(company);
});

// Delete a company
app.delete('/api/companies/:id', authMiddleware, (req, res) => {
  const { id } = req.params;
  const companyIds = db.userCompanyAccess[req.userId] || [];
  
  if (!companyIds.includes(id)) {
    return res.status(403).json({ error: 'Access denied' });
  }
  
  db.companies = db.companies.filter(c => c.id !== id);
  delete db.assessments[id];
  db.history = db.history.filter(h => h.companyId !== id);
  
  // Remove from all users' access
  for (const userId in db.userCompanyAccess) {
    db.userCompanyAccess[userId] = db.userCompanyAccess[userId].filter(cid => cid !== id);
  }
  
  saveDB(db);
  res.json({ success: true });
});

// ============================================================
// ASSESSMENT API ROUTES (Protected)
// ============================================================

// Get assessments for a company
app.get('/api/companies/:id/assessments', authMiddleware, (req, res) => {
  const { id } = req.params;
  const companyIds = db.userCompanyAccess[req.userId] || [];
  
  if (!companyIds.includes(id)) {
    return res.status(403).json({ error: 'Access denied' });
  }
  
  res.json(db.assessments[id] || {});
});

// Save assessment (with auto-propagation)
app.post('/api/companies/:id/assessments', authMiddleware, (req, res) => {
  const { id } = req.params;
  const companyIds = db.userCompanyAccess[req.userId] || [];
  
  if (!companyIds.includes(id)) {
    return res.status(403).json({ error: 'Access denied' });
  }
  
  const { framework, controlId, level, notes, evidence } = req.body;
  
  if (!db.assessments[id]) {
    db.assessments[id] = {};
  }
  
  const key = `${framework}:${controlId}`;
  const previousLevel = db.assessments[id][key]?.level || 0;
  
  // Save the assessment with enhanced data
  db.assessments[id][key] = {
    level,
    notes: notes || '',
    evidence: evidence || [],
    assessedBy: req.user.name,
    assessedById: req.userId,
    updatedAt: new Date().toISOString()
  };
  
  // Add to history
  db.history.push({
    companyId: id,
    frameworkId: framework,
    controlId: controlId,
    previousLevel: previousLevel,
    level: level,
    isPropagated: false,
    assessedBy: req.user.name,
    timestamp: new Date().toISOString()
  });
  
  // Auto-propagate to equivalent controls
  const equivalents = getEquivalentControls(framework, controlId);
  const propagated = [];
  
  for (const equiv of equivalents) {
    const eqKey = `${equiv.framework}:${equiv.controlId}`;
    const existing = db.assessments[id][eqKey];
    
    // Only propagate if the equivalent control has no assessment or lower level
    if (!existing || existing.level < level) {
      const prevLevel = existing?.level || 0;
      
      db.assessments[id][eqKey] = {
        level,
        notes: `Auto-propagated from ${framework}:${controlId}`,
        evidence: [],
        propagatedFrom: key,
        assessedBy: 'System (Auto-propagated)',
        updatedAt: new Date().toISOString()
      };
      
      db.history.push({
        companyId: id,
        frameworkId: equiv.framework,
        controlId: equiv.controlId,
        previousLevel: prevLevel,
        level: level,
        isPropagated: true,
        sourceControl: key,
        timestamp: new Date().toISOString()
      });
      
      propagated.push({
        framework: equiv.framework,
        controlId: equiv.controlId,
        level
      });
    }
  }
  
  saveDB(db);
  res.json({ success: true, propagated });
});

// Get assessment history
app.get('/api/companies/:id/history', authMiddleware, (req, res) => {
  const { id } = req.params;
  const companyIds = db.userCompanyAccess[req.userId] || [];
  
  if (!companyIds.includes(id)) {
    return res.status(403).json({ error: 'Access denied' });
  }
  
  const companyHistory = db.history
    .filter(h => h.companyId === id)
    .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
    .slice(0, 200);
  res.json(companyHistory);
});

// ============================================================
// MAPPINGS & ANALYTICS
// ============================================================

app.get('/api/mappings', (req, res) => {
  res.json(EQUIVALENCE_GROUPS);
});

// Get analytics/metrics for a company
app.get('/api/companies/:id/analytics', authMiddleware, (req, res) => {
  const { id } = req.params;
  const companyIds = db.userCompanyAccess[req.userId] || [];
  
  if (!companyIds.includes(id)) {
    return res.status(403).json({ error: 'Access denied' });
  }
  
  const assessments = db.assessments[id] || {};
  const history = db.history.filter(h => h.companyId === id);
  
  // Calculate various metrics
  const totalAssessments = Object.keys(assessments).length;
  const manualAssessments = Object.values(assessments).filter(a => !a.propagatedFrom).length;
  const propagatedAssessments = Object.values(assessments).filter(a => a.propagatedFrom).length;
  
  // Calculate trend (assessments over time)
  const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
  const recentHistory = history.filter(h => new Date(h.timestamp) > thirtyDaysAgo);
  
  // Time savings from propagation (estimated)
  const timeSavedMinutes = propagatedAssessments * 15; // Assume 15 min per control assessment
  
  res.json({
    totalAssessments,
    manualAssessments,
    propagatedAssessments,
    timeSavedMinutes,
    recentActivityCount: recentHistory.length,
    assessmentsByFramework: Object.keys(assessments).reduce((acc, key) => {
      const fw = key.split(':')[0];
      acc[fw] = (acc[fw] || 0) + 1;
      return acc;
    }, {})
  });
});

// ============================================================
// AI ANALYSIS PROXY (Enhanced)
// ============================================================

app.post('/api/ai/analyze', authMiddleware, async (req, res) => {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    return res.json({ error: 'ANTHROPIC_API_KEY not configured. Set the environment variable to enable AI analysis.' });
  }

  try {
    const { prompt, analysisType, type } = req.body;
    
    // Enhanced system prompt for consulting-grade output with clean HTML
    let systemPrompt = `You are a senior partner at a Big 5 consulting firm (like Deloitte, EY, McKinsey, KPMG, or PwC) specializing in cybersecurity, compliance, and risk management.

Your expertise spans ISO 27001:2022, NIST CSF 2.0, NIST 800-171 Rev 2, CMMC Level 2, SOC 2 Type II, HIPAA Security Rule, PCI DSS 4.0, and GDPR.

When providing analysis, you must:
1. Use professional consulting language and structure
2. Provide executive-ready insights with clear recommendations
3. Include specific control IDs and cross-framework references
4. Prioritize findings by risk level (Critical, High, Medium, Low)
5. Use industry benchmarks and best practices
6. Reference relevant regulatory deadlines and compliance requirements
7. Focus on practical, actionable steps rather than speculative cost estimates

CRITICAL: Format your responses using clean HTML (NOT Markdown). Use these HTML tags:
- <h2>Section Title</h2> for main sections
- <h3>Subsection Title</h3> for subsections
- <p>Paragraph text</p> for paragraphs
- <ul><li>Item</li></ul> for bullet lists
- <ol><li>Step</li></ol> for numbered lists
- <strong>bold text</strong> for emphasis
- <table><thead><tr><th>Header</th></tr></thead><tbody><tr><td>Data</td></tr></tbody></table> for tables

Do NOT use Markdown syntax like ##, **, -, or |. Use only clean HTML tags.
Do NOT include speculative dollar amounts, cost estimates, or ROI calculations as these vary significantly by organization.

Your analysis should be actionable, specific, and boardroom-ready.`;

    // Special prompt for Audit Readiness
    if (type === 'audit') {
      systemPrompt += `

For Audit Readiness analysis, structure your response with these exact sections:
1. <h2>Executive Summary</h2> - Brief overview of audit readiness status
2. <h2>Before the Audit</h2> - Preparation checklist, documentation requirements, evidence gathering
3. <h2>During the Audit</h2> - What to expect, key personnel roles, communication protocols
4. <h2>After the Audit</h2> - Findings remediation, continuous improvement, certification maintenance
5. <h2>Expected Auditor Questions</h2> - Common questions auditors will ask, organized by control domain
6. <h2>Risk Areas & Recommendations</h2> - Specific gaps that may raise auditor concerns`;
    }

    // Special prompt for Implementation Roadmap
    if (type === 'roadmap') {
      systemPrompt += `

For Implementation Roadmap, you MUST:
1. Complete ALL 7 sections requested - do not stop mid-section
2. Keep tables concise but complete - every row must be filled
3. The Deliverables Register MUST include all 15 deliverables listed
4. The Gantt Timeline MUST show all 12 weeks
5. Prioritize completeness over verbosity - use short, clear descriptions
6. If running low on space, make descriptions more concise rather than omitting sections`;
    }

    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-20250514',
        max_tokens: 8192,
        messages: [
          {
            role: 'user',
            content: prompt
          }
        ],
        system: systemPrompt
      })
    });

    const data = await response.json();
    
    if (data.error) {
      return res.json({ error: data.error.message });
    }
    
    const text = data.content?.[0]?.text || 'No response generated';
    res.json({ analysis: text });
  } catch (error) {
    console.error('AI Analysis error:', error);
    res.json({ error: `AI Analysis failed: ${error.message}` });
  }
});

// ============================================================
// SERVE THE APP
// ============================================================

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  const googleEnabled = GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET ? '✓' : '○';
  const githubEnabled = GITHUB_CLIENT_ID && GITHUB_CLIENT_SECRET ? '✓' : '○';
  const microsoftEnabled = MICROSOFT_CLIENT_ID && MICROSOFT_CLIENT_SECRET ? '✓' : '○';
  const emailEnabled = emailTransporter ? '✓' : '○';
  
  console.log(`
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║   Audit Platform v3.2.0 - Enterprise Compliance Assessment Platform ║
║                                                                      ║
║   Server running at ${BASE_URL}                                      
║                                                                      ║
║   Admin Accounts:                                                    ║
║   • admin / @dm1n1! (password login)                                 ║
║   • newreal8y@gmail.com (Google OAuth)                               ║
║                                                                      ║
║   Authentication:                                                    ║
║   ${googleEnabled} Google OAuth ${GOOGLE_CLIENT_ID ? '(configured)' : '(set GOOGLE_CLIENT_ID & GOOGLE_CLIENT_SECRET)'}
║   ${microsoftEnabled} Microsoft OAuth ${MICROSOFT_CLIENT_ID ? '(configured)' : '(set MICROSOFT_CLIENT_ID & MICROSOFT_CLIENT_SECRET)'}
║   ${githubEnabled} GitHub OAuth ${GITHUB_CLIENT_ID ? '(configured)' : '(set GITHUB_CLIENT_ID & GITHUB_CLIENT_SECRET)'}
║   ${emailEnabled} Email/SMTP ${emailTransporter ? '(configured)' : '(set SMTP_USER & SMTP_PASS)'}
║                                                                      ║
║   Features:                                                          ║
║   ✓ 627 controls across 8 frameworks                                 ║
║   ✓ Admin Panel with User Management & Analytics                     ║
║   ✓ User Feedback System                                             ║
║   ✓ Password Reset via Email                                         ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
  `);
});
