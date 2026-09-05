require('dotenv').config();
const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const { UAParser } = require('ua-parser-js');
const { OAuth2Client } = require('google-auth-library');
const mongoose = require('mongoose');
const multer = require('multer');
const sharp = require('sharp');

const app = express();
app.set('trust proxy', true);

const PORT = process.env.PORT || 3000;
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || '').toLowerCase().split(',').map(e => e.trim()).filter(Boolean);
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const SESSION_SECRET = process.env.SESSION_SECRET || 'change_this_secret';
const MONGODB_URI = process.env.MONGODB_URI;

const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);

// Allowed photo categories — must match the "folder" values used in public/index.html's CATEGORIES list
const ALLOWED_CATEGORIES = ['hall', 'bedroom', 'tv', 'balcony', 'wall'];

// Photos are stored directly inside MongoDB (no third-party image service needed).
// Keep per-photo size small so a single photo document stays well under MongoDB's 16MB document limit.
const MAX_PHOTO_SIZE = 10 * 1024 * 1024; // 10MB per photo
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_PHOTO_SIZE, files: 20 }, // max 20 photos per upload batch
  fileFilter: (req, file, cb) => {
    if (!file.mimetype.startsWith('image/')) return cb(new Error('Only image files are allowed'));
    cb(null, true);
  }
});

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
      serverSelectionTimeoutMS: 8000, // Timeout fast taaki page na ruke
      connectTimeoutMS: 8000
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

const PhotoSchema = new mongoose.Schema({
  category: { type: String, index: true }, // e.g. "hall", "bedroom" — matches CATEGORIES[].folder on the site
  data: Buffer,        // the actual photo bytes, stored directly in MongoDB
  contentType: String, // e.g. "image/jpeg"
  uploadedAt: { type: Date, default: Date.now }
});

const Visit = mongoose.models.Visit || mongoose.model('Visit', VisitSchema);
const BlockedIP = mongoose.models.BlockedIP || mongoose.model('BlockedIP', BlockedIPSchema);
const Photo = mongoose.models.Photo || mongoose.model('Photo', PhotoSchema);

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

  try {
    await connectDB();
    const rawIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || req.ip || '';
    const clientIp = rawIp.split(',')[0].trim();
    const isBlocked = await BlockedIP.findOne({ ip: clientIp });
    if (isBlocked) {
      return res.status(403).send(`
        <div style="font-family:sans-serif;text-align:center;padding:80px 20px;background:#111;color:#eee;">
          <h2>Access Blocked</h2>
          <p>You have been blocked from viewing this site.</p>
        </div>
     `);
    }
  } catch (e) {
    // agar DB check fail ho jaye, galti se kisi ko block mat karo
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
    if (!ADMIN_EMAIL.includes((data.email || '').toLowerCase().trim())) return false;
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

    if (!payload.email_verified || !ADMIN_EMAIL.includes(email)) {
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
   PHOTO UPLOAD — stored directly in MongoDB, no third-party service
   ============================================================ */
app.post('/api/admin/photos/upload', requireAdmin, (req, res) => {
  upload.array('photos', 20)(req, res, async (err) => {
    if (err) {
      // multer errors (file too big, too many files, wrong type) land here — respond cleanly instead of crashing
      const msg = err.code === 'LIMIT_FILE_SIZE'
        ? `Each photo must be under ${MAX_PHOTO_SIZE / (1024 * 1024)}MB.`
        : (err.message || 'Upload failed.');
      return res.status(400).json({ error: msg });
    }

    try {
      const category = (req.body.category || '').toLowerCase().trim();
      if (!ALLOWED_CATEGORIES.includes(category)) {
        return res.status(400).json({ error: 'Invalid category' });
      }
      if (!req.files || !req.files.length) {
        return res.status(400).json({ error: 'No files received' });
      }

      const db = await connectDB();
      if (!db) return res.status(503).json({ error: 'Database not reachable right now. Try again in a moment.' });

      const saved = [];
      for (const file of req.files) {
        // Resize (max 1600px wide) + compress to JPEG - smaller file, quality stays sharp
        const compressed = await sharp(file.buffer)
          .rotate() // auto-fix orientation from phone cameras
          .resize({ width: 1600, withoutEnlargement: true })
          .jpeg({ quality: 82 })
          .toBuffer();

        const doc = await Photo.create({
          category,
          data: compressed,
          contentType: 'image/jpeg'
        });
        saved.push({ _id: doc._id, category: doc.category, uploadedAt: doc.uploadedAt });
      }

      res.json({ ok: true, uploaded: saved.length, photos: saved });
    } catch (err) {
      console.error('Upload error:', err.message);
      res.status(500).json({ error: 'Upload failed. Please try again.' });
    }
  });
});

app.get('/api/admin/photos/:category', requireAdmin, async (req, res) => {
  try {
    await connectDB();
    const category = (req.params.category || '').toLowerCase().trim();
    const photos = await Photo.find({ category }).sort({ uploadedAt: -1 }).select('_id uploadedAt');
    res.json(photos);
  } catch {
    res.json([]);
  }
});

app.delete('/api/admin/photos/:id', requireAdmin, async (req, res) => {
  try {
    await connectDB();
    await Photo.deleteOne({ _id: req.params.id });
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'Delete failed' });
  }
});

/* ============================================================
   PUBLIC PHOTOS API — used by the website to show uploaded photos
   ============================================================ */
app.get('/api/photos/:category', async (req, res) => {
  try {
    await connectDB();
    const category = (req.params.category || '').toLowerCase().trim();
    if (!ALLOWED_CATEGORIES.includes(category)) return res.json([]);
    const photos = await Photo.find({ category }).sort({ uploadedAt: -1 }).select('_id');
    res.json(photos.map(p => `/api/photos/image/${p._id}`));
  } catch {
    res.json([]);
  }
});

// Serves the actual image bytes for a single uploaded photo (used as <img src="...">)
app.get('/api/photos/image/:id', async (req, res) => {
  try {
    await connectDB();
    const photo = await Photo.findById(req.params.id);
    if (!photo || !photo.data) return res.status(404).end();
    res.set('Content-Type', photo.contentType || 'image/jpeg');
    res.set('Cache-Control', 'public, max-age=604800'); // cache for 7 days — reduces load on the DB
    res.send(photo.data);
  } catch {
    res.status(404).end();
  }
});

/* ============================================================
   DAILY VISITS STATS (for the admin dashboard graph)
   ============================================================ */
app.get('/api/admin/stats/daily', requireAdmin, async (req, res) => {
  try {
    await connectDB();
    const since = new Date();
    since.setDate(since.getDate() - 13); // last 14 days
    since.setHours(0, 0, 0, 0);

    const raw = await Visit.aggregate([
      { $match: { time: { $gte: since } } },
      { $group: {
          _id: { $dateToString: { format: '%Y-%m-%d', date: '$time' } },
          count: { $sum: 1 }
      } }
    ]);
    const byDate = Object.fromEntries(raw.map(r => [r._id, r.count]));

    const days = [];
    for (let i = 13; i >= 0; i--) {
      const d = new Date();
      d.setDate(d.getDate() - i);
      const key = d.toISOString().slice(0, 10);
      days.push({ date: key, count: byDate[key] || 0 });
    }
    res.json(days);
  } catch {
    res.json([]);
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