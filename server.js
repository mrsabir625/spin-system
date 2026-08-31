// Spin World Ceiling System — Website + Admin Panel server
// Serves the public website, logs visits, blocks banned IPs,
// and exposes an admin dashboard protected by Google Sign-In
// restricted to a single email address.

require('dotenv').config();
const express = require('express');
const path = require('path');
const fs = require('fs');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const { UAParser } = require('ua-parser-js');
const { OAuth2Client } = require('google-auth-library');

const app = express();
app.set('trust proxy', true); // needed so req.ip is the real visitor IP once hosted online

const PORT = process.env.PORT || 3000;
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || '').toLowerCase().trim();
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const SESSION_SECRET = process.env.SESSION_SECRET || 'change_this_secret';

const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);

app.use(express.json());
app.use(cookieParser());

/* ============================================================
   SIMPLE FILE-BASED STORAGE (no database needed)
   ============================================================ */
const DATA_DIR = path.join(__dirname, 'data');
const VISITS_FILE = path.join(DATA_DIR, 'visits.json');
const BLOCKED_FILE = path.join(DATA_DIR, 'blocked-ips.json');
const MAX_VISITS_STORED = 2000; // keeps the file from growing forever

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR);
if (!fs.existsSync(VISITS_FILE)) fs.writeFileSync(VISITS_FILE, '[]');
if (!fs.existsSync(BLOCKED_FILE)) fs.writeFileSync(BLOCKED_FILE, '[]');

function readJSON(file) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch { return []; }
}
function writeJSON(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

/* ============================================================
   VISIT LOGGING + IP BLOCK MIDDLEWARE
   (applies to the public website only, not /admin or /api routes)
   ============================================================ */
function logVisit(req) {
  const ua = new UAParser(req.headers['user-agent']);
  const result = ua.getResult();
  const visits = readJSON(VISITS_FILE);
  visits.unshift({
    ip: req.ip,
    path: req.path,
    device: result.device.model || result.device.vendor || 'Desktop/Laptop',
    deviceType: result.device.type || 'desktop',
    browser: result.browser.name || 'Unknown',
    os: result.os.name || 'Unknown',
    time: new Date().toISOString()
  });
  writeJSON(VISITS_FILE, visits.slice(0, MAX_VISITS_STORED));
}

app.use((req, res, next) => {
  if (req.path.startsWith('/admin') || req.path.startsWith('/api')) return next();

  const blocked = readJSON(BLOCKED_FILE);
  if (blocked.some(b => b.ip === req.ip)) {
    return res.status(403).send(`
      <div style="font-family:sans-serif;text-align:center;padding:80px 20px;">
        <h2>Access Blocked</h2>
        <p>You have been blocked from viewing this site. Contact the site owner if you think this is a mistake.</p>
      </div>
    `);
  }

  // only log real page loads, not every asset (image/css/js) request
  if (req.path === '/' || req.path.endsWith('.html')) logVisit(req);
  next();
});

app.use(express.static(path.join(__dirname, 'public')));

/* ============================================================
   ADMIN AUTH — Google Sign-In restricted to ADMIN_EMAIL
   ============================================================ */
function makeSessionToken() {
  return crypto.randomBytes(32).toString('hex');
}
const activeSessions = new Set(); // simple in-memory session store

function requireAdmin(req, res, next) {
  const token = req.cookies.admin_session;
  if (token && activeSessions.has(token)) return next();
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

    const token = makeSessionToken();
    activeSessions.add(token);
    res.cookie('admin_session', token, {
      httpOnly: true,
      sameSite: 'lax',
      maxAge: 12 * 60 * 60 * 1000 // 12 hours
    });
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(401).json({ error: 'Google verification failed.' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  activeSessions.delete(req.cookies.admin_session);
  res.clearCookie('admin_session');
  res.json({ ok: true });
});

app.get('/api/auth/status', (req, res) => {
  const token = req.cookies.admin_session;
  res.json({ authenticated: !!(token && activeSessions.has(token)) });
});

/* ============================================================
   ADMIN API — visitors + block/unblock (all require login)
   ============================================================ */
app.get('/api/admin/visitors', requireAdmin, (req, res) => {
  res.json(readJSON(VISITS_FILE).slice(0, 200));
});

app.get('/api/admin/blocked', requireAdmin, (req, res) => {
  res.json(readJSON(BLOCKED_FILE));
});

app.post('/api/admin/block', requireAdmin, (req, res) => {
  const { ip } = req.body;
  if (!ip) return res.status(400).json({ error: 'ip required' });
  const blocked = readJSON(BLOCKED_FILE);
  if (!blocked.some(b => b.ip === ip)) {
    blocked.unshift({ ip, blockedAt: new Date().toISOString() });
    writeJSON(BLOCKED_FILE, blocked);
  }
  res.json({ ok: true });
});

app.post('/api/admin/unblock', requireAdmin, (req, res) => {
  const { ip } = req.body;
  const blocked = readJSON(BLOCKED_FILE).filter(b => b.ip !== ip);
  writeJSON(BLOCKED_FILE, blocked);
  res.json({ ok: true });
});

/* ============================================================
   SERVE ADMIN DASHBOARD PAGE
   ============================================================ */
app.use('/admin', express.static(path.join(__dirname, 'admin')));

app.listen(PORT, () => {
  console.log(`Website running at http://localhost:${PORT}`);
  console.log(`Admin panel running at http://localhost:${PORT}/admin`);
});
