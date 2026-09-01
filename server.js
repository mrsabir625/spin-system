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
   DATABASE CONNECTION & MODELS
   ============================================================ */
let isConnected = false;
async function connectDB() {
  if (isConnected || !MONGODB_URI) return;
  try {
    const db = await mongoose.connect(MONGODB_URI);
    isConnected = db.connections[0].readyState === 1;
  } catch (err) {
    console.error('MongoDB connection error:', err);
  }
}
connectDB();

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
   LOGGING & BLOCK MIDDLEWARE
   ============================================================ */
function getClientIp(req) {
  const rawIp = [
    req.headers['x-forwarded-for'],
    req.socket && req.socket.remoteAddress,
    req.ip
  ].filter(Boolean).join(',');

  return rawIp.split(',')[0].trim();
}

async function logVisit(req) {
  try {
    await connectDB();
    const ua = new UAParser(req.headers['user-agent']);
    const result = ua.getResult();
    const clientIp = getClientIp(req);

    await Visit.create({
      ip: clientIp,
      path: req.path,
      device: `${result.device.model || ''}${result.device.vendor || ''} Desktop/Laptop`,
      deviceType: result.device.type || 'desktop',
      browser: result.browser.name || 'Unknown',
      os: result.os.name || 'Unknown'
    });
  } catch (e) {
    console.error('Visit log error:', e);
  }
}

app.use(async (req, res, next) => {
  if (req.path.startsWith('/admin') || req.path.startsWith('/api')) return next();

  await connectDB();
  const clientIp = getClientIp(req);

  const isBlocked = await BlockedIP.findOne({ ip: clientIp });
  if (isBlocked) {
    return res.status(403).send(`
      <div style="font-family:sans-serif;text-align:center;padding:80px 20px;">
        <h2>Access Blocked</h2>
        <p>You have been blocked from viewing this site.</p>
      </div>
    `);
  }

  if (req.path === '/' || req.path.endsWith('.html')) {
    logVisit(req);
  }
  next();
});

app.use(express.static(path.join(__dirname, 'public')));

/* ============================================================
   ADMIN AUTH (STATELESS SIGNED TOKEN)
   ============================================================ */
function makeSignedToken(email) {
  const expiry = Date.now() + 12 * 60 * 60 * 1000;
  const payload = `${email}:${expiry}`;
  const hmac = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('hex');
  return `${payload}:${hmac}`;
}

function verifySignedToken(token) {
  if (!token) return false;
  const parts = token.split(':');
  if (parts.length !== 3) return false;
  const [email, expiry, hmac] = parts;
  if (Date.now() > Number(expiry)) return false;
  if (email !== ADMIN_EMAIL) return false;
  const expectedHmac = crypto.createHmac('sha256', SESSION_SECRET).update(`${email}:${expiry}`).digest('hex');
  if (hmac.length !== expectedHmac.length) return false;
  return crypto.timingSafeEqual(Buffer.from(hmac), Buffer.from(expectedHmac));
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
      httpOnly: true,
      secure: true,
      sameSite: 'lax',
      maxAge: 12 * 60 * 60 * 1000
    });
    res.json({ ok: true });
  } catch (err) {
    res.status(401).json({ error: 'Google verification failed.' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('admin_session', { httpOnly: true, secure: true, sameSite: 'lax' });
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
  await connectDB();
  const visits = await Visit.find().sort({ time: -1 }).limit(200);
  res.json(visits);
});

app.get('/api/admin/blocked', requireAdmin, async (req, res) => {
  await connectDB();
  const blocked = await BlockedIP.find().sort({ blockedAt: -1 });
  res.json(blocked);
});

app.post('/api/admin/block', requireAdmin, async (req, res) => {
  await connectDB();
  const { ip } = req.body;
  if (!ip) return res.status(400).json({ error: 'ip required' });
  await BlockedIP.updateOne({ ip }, { ip, blockedAt: new Date() }, { upsert: true });
  res.json({ ok: true });
});

app.post('/api/admin/unblock', requireAdmin, async (_req, res) => {
  await connectDB();
  const { ip } = _req.body;
  if (!ip) return res.status(400).json({ error: 'ip required' });
  await BlockedIP.deleteOne({ ip });
  res.json({ ok: true });
});

/* ============================================================
   SERVE ADMIN DASHBOARD
   ============================================================ */
app.use('/admin', express.static(path.join(__dirname, 'admin')));

app.listen(PORT, () => {
  console.log(`Website running at http://localhost:${PORT}`);
});