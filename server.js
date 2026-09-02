 require('dotenv').config();
const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const { UAParser } = require('ua-parser-js');
const { OAuth2Client } = require('google-auth-library');
const mongoose = require('mongoose');

const app = express();
app.set('trust proxy', true);

const PORT = process.env.PORT || 3000;
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || '').toLowerCase().trim();
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const SESSION_SECRET = process.env.SESSION_SECRET || 'change_this_secret';
const MONGODB_URI = process.env.MONGODB_URI;

const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);

app.use(express.json());
app.use(cookieParser());

/* ============================================================
   DATABASE CONNECTION (Non-Blocking Serverless Cache)
   ============================================================ */
let cachedConn = null;

async function connectDB() {
  if (cachedConn && mongoose.connection.readyState === 1) {
    return cachedConn;
  }
  if (!MONGODB_URI) return null;

  try {
    cachedConn = await mongoose.connect(MONGODB_URI, {
      serverSelectionTimeoutMS: 2500, // Timeout fast taaki page na ruke
      connectTimeoutMS: 2500
    });
    return cachedConn;
  } catch (err) {
    console.error('MongoDB quick-fail error:', err.message);
    return null;
  }
}

const VisitSchema = new mongoose.Schema({
  ip: String,
  path: String,
  device: String,
  deviceType: String,
  browser: String,
  os: String,
  time: { type: Date, default: Date.now }
});

const BlockedIPSchema = new mongoose.Schema({
  ip: { type: String, unique: true },
  blockedAt: { type: Date, default: Date.now }
});

const Visit = mongoose.models.Visit || mongoose.model('Visit', VisitSchema);
const BlockedIP = mongoose.models.BlockedIP || mongoose.model('BlockedIP', BlockedIPSchema);

/* ============================================================
   VISITOR LOGGING
   ============================================================ */
async function logVisitorData(req) {
  try {
    const db = await connectDB();
    if (!db) return;

    const ua = new UAParser(req.headers['user-agent']);
    const result = ua.getResult();
    const rawIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || req.ip || '';
    const clientIp = rawIp.split(',')[0].trim();

    await Visit.create({
      ip: clientIp || 'Unknown IP',
      path: req.path || '/',
      device: result.device.model || result.device.vendor || 'Desktop/Laptop',
      deviceType: result.device.type || 'desktop',
      browser: result.browser.name || 'Unknown',
      os: result.os.name || 'Unknown',
      time: new Date()
    });
  } catch (e) {
    // Ignore error in background
  }
}

// Fast Middleware (Never blocks response)
app.use(async (req, res, next) => {
  if (req.path.startsWith('/admin') || req.path.startsWith('/api')) {
    return next();
  }

  const isPageView = req.path === '/' || req.path.endsWith('.html') || !path.extname(req.path);
  if (isPageView) {
   await logVisitorData(req);
  }
  next();
});

// Static assets
app.use(express.static(path.join(__dirname, 'public')));

/* ============================================================
   ADMIN AUTH (Stateless Token)
   ============================================================ */
function makeSignedToken(email) {
  const expiry = Date.now() + 24 * 60 * 60 * 1000;
  const rawData = JSON.stringify({ email, expiry });
  const base64Data = Buffer.from(rawData).toString('base64');
  const signature = crypto.createHmac('sha256', SESSION_SECRET).update(base64Data).digest('hex');
  return `${base64Data}.${signature}`;
}

function verifySignedToken(token) {
  if (!token || typeof token !== 'string') return false;
  const parts = token.split('.');
  if (parts.length !== 2) return false;

  const [base64Data, signature] = parts;
  const expectedSignature = crypto.createHmac('sha256', SESSION_SECRET).update(base64Data).digest('hex');
  if (signature !== expectedSignature) return false;
 try {
    const data = JSON.parse(Buffer.from(base64Data, 'base64').toString('utf8'));
    if (Date.now() > data.expiry) return false;
    if (data.email.toLowerCase().trim() !== ADMIN_EMAIL) return false;
    return true;
  } catch {
    return false;
  }
}

function requireAdmin(req, res, next) {
  const token = req.cookies.admin_session;
  if (verifySignedToken(token)) return next();
  return res.status(401).json({ error: 'Not authenticated' });
}

app.post('/api/auth/google', async (req, res) => {
  try {
    const { credential } = req.body;
    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: GOOGLE_CLIENT_ID
    });
    const payload = ticket.getPayload();
    const email = (payload.email || '').toLowerCase().trim();

    if (!payload.email_verified || email !== ADMIN_EMAIL) {
      return res.status(403).json({ error: 'This Google account is not authorized.' });
    }

    const token = makeSignedToken(email);
    res.cookie('admin_session', token, {
      path: '/',
      httpOnly: true,
      secure: true,
      sameSite: 'lax',
      maxAge: 24 * 60 * 60 * 1000
    });
    res.json({ ok: true });
  } catch (err) {
    res.status(401).json({ error: 'Google verification failed.' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('admin_session', { path: '/', httpOnly: true, secure: true, sameSite: 'lax' });
  res.json({ ok: true });
});

app.get('/api/auth/status', (req, res) => {
  const token = req.cookies.admin_session;
  res.json({ authenticated: verifySignedToken(token) });
});

/* ============================================================
   ADMIN APIS
   ============================================================ */
app.get('/api/admin/visitors', requireAdmin, async (req, res) => {
  try {
    await connectDB();
    const visits = await Visit.find().sort({ time: -1 }).limit(200);
    res.json(visits);
  } catch {
    res.json([]);
  }
});

app.get('/api/admin/blocked', requireAdmin, async (req, res) => {
  try {
    await connectDB();
    const blocked = await BlockedIP.find().sort({ blockedAt: -1 });
    res.json(blocked);
  } catch {
    res.json([]);
  }
});

app.post('/api/admin/block', requireAdmin, async (req, res) => {
  try {
    await connectDB();
    const { ip } = req.body;
    if (!ip) return res.status(400).json({ error: 'ip required' });
    await BlockedIP.updateOne({ ip }, { ip, blockedAt: new Date() }, { upsert: true });
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: 'DB error' });
  }
});

app.post('/api/admin/unblock', requireAdmin, async (req, res) => {
  try {
    await connectDB();
    const { ip } = req.body;
    await BlockedIP.deleteOne({ ip });
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: 'DB error' });
  }
});

/* ============================================================
   EXPLICIT SERVE
   ============================================================ */
app.use('/admin', express.static(path.join(__dirname, 'public', 'admin')));
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});