'use strict';

require('dotenv').config();

const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const http = require('http');
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const Database = require('better-sqlite3');
const nodemailer = require('nodemailer');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const ROOT = __dirname;
const PUBLIC_DIR = path.join(ROOT, 'public');
const DATA_DIR = path.resolve(process.env.DATA_DIR || path.join(ROOT, 'data'));
const UPLOAD_DIR = path.resolve(process.env.UPLOAD_DIR || path.join(ROOT, 'uploads'));
const MAX_CV_MB = Math.max(1, Math.min(Number(process.env.MAX_CV_MB || 8), 12));
const MAX_CV_BYTES = MAX_CV_MB * 1024 * 1024;

fs.mkdirSync(DATA_DIR, { recursive: true, mode: 0o700 });
fs.mkdirSync(UPLOAD_DIR, { recursive: true, mode: 0o700 });

if (process.env.TRUST_PROXY) app.set('trust proxy', Number(process.env.TRUST_PROXY) || 1);
app.disable('x-powered-by');

const db = new Database(path.join(DATA_DIR, 'gsea.sqlite'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
  CREATE TABLE IF NOT EXISTS submissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    form_type TEXT NOT NULL CHECK(form_type IN ('QuoteRequest','JobApplication','ContactMessage')),
    name TEXT NOT NULL,
    phone TEXT NOT NULL,
    email TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    cv_filename TEXT,
    cv_stored_name TEXT,
    created_at TEXT NOT NULL,
    ip_hash TEXT,
    user_agent TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_submissions_created_at ON submissions(created_at);
  CREATE INDEX IF NOT EXISTS idx_submissions_form_type ON submissions(form_type);
`);

const insertSubmission = db.prepare(`
  INSERT INTO submissions
  (form_type, name, phone, email, payload_json, cv_filename, cv_stored_name, created_at, ip_hash, user_agent)
  VALUES (@form_type, @name, @phone, @email, @payload_json, @cv_filename, @cv_stored_name, @created_at, @ip_hash, @user_agent)
`);

const csrfTokens = new Map();
const CSRF_TTL_MS = 60 * 60 * 1000;
function issueCsrfToken() {
  const token = crypto.randomBytes(32).toString('hex');
  csrfTokens.set(token, Date.now() + CSRF_TTL_MS);
  return token;
}
function cleanCsrfStore() {
  const now = Date.now();
  for (const [token, expires] of csrfTokens) if (expires <= now) csrfTokens.delete(token);
}
setInterval(cleanCsrfStore, 15 * 60 * 1000).unref();

function hashIp(ip) {
  return crypto.createHash('sha256').update(`${ip}|${process.env.IP_HASH_SALT || 'gsea-change-this-salt'}`).digest('hex');
}
function cleanText(value, max = 2000) {
  return String(value ?? '').replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '').trim().slice(0, max);
}
function validEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/i.test(value);
}
function validPhone(value) {
  return /^[+()\d\s.-]{7,30}$/.test(value);
}
function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, c => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' })[c]);
}
function mailConfigured() {
  return Boolean(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS && process.env.COMPANY_EMAIL);
}

const transporter = mailConfigured() ? nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT || 587),
  secure: String(process.env.SMTP_SECURE).toLowerCase() === 'true',
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
  connectionTimeout: 10000,
  greetingTimeout: 10000,
  socketTimeout: 15000
}) : null;

async function sendNotification(submission, cvPath) {
  if (!transporter) return false;
  const rows = Object.entries(submission.payload)
    .filter(([key]) => key !== 'website')
    .map(([key, value]) => `<tr><td style="padding:6px 10px;border:1px solid #ddd"><b>${escapeHtml(key)}</b></td><td style="padding:6px 10px;border:1px solid #ddd">${escapeHtml(value)}</td></tr>`)
    .join('');

  const attachments = cvPath ? [{ filename: submission.cv_filename, path: cvPath }] : [];
  await transporter.sendMail({
    from: process.env.SMTP_FROM || process.env.SMTP_USER,
    to: process.env.COMPANY_EMAIL,
    replyTo: submission.email,
    subject: `[GSEA] ${submission.form_type} — ${submission.name}`,
    text: `New ${submission.form_type} from ${submission.name} (${submission.email}, ${submission.phone}).`,
    html: `<h2>G.S.E.A — ${escapeHtml(submission.form_type)}</h2><p><b>Name:</b> ${escapeHtml(submission.name)}<br><b>Phone:</b> ${escapeHtml(submission.phone)}<br><b>Email:</b> ${escapeHtml(submission.email)}</p><table style="border-collapse:collapse">${rows}</table>`,
    attachments
  });
  return true;
}

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      baseUri: ["'self'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
      imgSrc: ["'self'", 'data:'],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc: ["'self'", 'https://fonts.gstatic.com'],
      scriptSrc: ["'self'"],
      connectSrc: ["'self'"],
      frameSrc: ['https://www.google.com'],
      formAction: ["'self'"],
      upgradeInsecureRequests: process.env.NODE_ENV === 'production' ? [] : null
    }
  },
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
}));
app.use(express.json({ limit: '32kb' }));
app.use(express.urlencoded({ extended: false, limit: '32kb' }));

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { message: 'Too many requests. Please try again later.' }
});
app.use('/api/', apiLimiter);

app.get('/api/health', (_req, res) => res.json({ ok: true }));
app.get('/api/csrf', (_req, res) => {
  const token = issueCsrfToken();
  res.cookie('gsea_csrf', token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: CSRF_TTL_MS,
    path: '/'
  });
  res.set('Cache-Control', 'no-store');
  res.json({ token });
});

function csrfGuard(req, res, next) {
  const cookieToken = req.headers.cookie?.match(/(?:^|;\s*)gsea_csrf=([^;]+)/)?.[1];
  const headerToken = req.get('x-csrf-token');
  const valid = cookieToken && headerToken && cookieToken === headerToken && csrfTokens.has(headerToken) && csrfTokens.get(headerToken) > Date.now();
  if (!valid) return res.status(403).json({ message: 'Security token expired. Refresh the page and try again.' });
  next();
}

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_CV_BYTES, files: 1 },
  fileFilter: (_req, file, cb) => {
    const allowed = new Set(['application/pdf','application/msword','application/vnd.openxmlformats-officedocument.wordprocessingml.document']);
    if (!allowed.has(file.mimetype)) return cb(new Error('Only PDF, DOC or DOCX files are allowed.'));
    cb(null, true);
  }
});

function fileSignatureOk(file) {
  if (!file) return true;
  const b = file.buffer;
  if (file.mimetype === 'application/pdf') return b.subarray(0, 5).toString() === '%PDF-';
  if (file.mimetype === 'application/msword') return b.subarray(0, 8).equals(Buffer.from('D0CF11E0A1B11AE1', 'hex'));
  if (file.mimetype === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document') return b.subarray(0, 2).toString() === 'PK';
  return false;
}

function normalizeForm(formType, body) {
  const base = {
    name: cleanText(body.name, 120),
    phone: cleanText(body.phone, 40),
    email: cleanText(body.email, 160).toLowerCase()
  };
  const payload = { ...body };
  delete payload.formType;
  delete payload.website;
  for (const [k, v] of Object.entries(payload)) payload[k] = cleanText(v, 4000);
  if (!base.name || !base.phone || !base.email) throw new Error('Please fill in all required fields.');
  if (!validEmail(base.email)) throw new Error('Please enter a valid email address.');
  if (!validPhone(base.phone)) throw new Error('Please enter a valid phone number.');
  if (formType === 'QuoteRequest' && (!payload.facilityType || !payload.address)) throw new Error('Facility type and address are required.');
  if (formType === 'JobApplication' && !payload.position) throw new Error('Position is required.');
  if (formType === 'ContactMessage' && !payload.message) throw new Error('Message is required.');
  return { ...base, payload };
}

app.post('/api/submitSiteForm', csrfGuard, upload.single('cv'), async (req, res) => {
  let storedPath = null;
  try {
    const formType = cleanText(req.body.formType, 40);
    if (!['QuoteRequest','JobApplication','ContactMessage'].includes(formType)) return res.status(400).json({ message: 'Invalid form type.' });

    // Honeypot: bots that fill this hidden field get a harmless success response.
    if (cleanText(req.body.website, 200)) return res.json({ ok: true });

    if (formType !== 'JobApplication' && req.file) return res.status(400).json({ message: 'File uploads are only accepted for job applications.' });
    if (formType === 'JobApplication' && req.file && !fileSignatureOk(req.file)) return res.status(400).json({ message: 'The uploaded file does not match an allowed document type.' });

    const normalized = normalizeForm(formType, req.body);
    let cvStoredName = null;
    let cvFilename = null;
    if (req.file) {
      cvStoredName = `${crypto.randomUUID()}${path.extname(req.file.originalname).toLowerCase()}`;
      storedPath = path.join(UPLOAD_DIR, cvStoredName);
      fs.writeFileSync(storedPath, req.file.buffer, { mode: 0o600, flag: 'wx' });
      cvFilename = cleanText(path.basename(req.file.originalname), 180);
    }

    const submission = {
      form_type: formType,
      name: normalized.name,
      phone: normalized.phone,
      email: normalized.email,
      payload: normalized.payload,
      cv_filename: cvFilename,
      cv_stored_name: cvStoredName,
      created_at: new Date().toISOString(),
      ip_hash: hashIp(req.ip),
      user_agent: cleanText(req.get('user-agent'), 500)
    };

    const info = insertSubmission.run({
      ...submission,
      payload_json: JSON.stringify(submission.payload)
    });

    let notified = false;
    try {
      notified = await sendNotification(submission, storedPath);
    } catch (mailError) {
      console.error('SMTP notification failed:', mailError.message);
    }

    res.status(201).json({ ok: true, id: info.lastInsertRowid, notified });
  } catch (error) {
    if (storedPath) fs.rmSync(storedPath, { force: true });
    const message = error instanceof multer.MulterError && error.code === 'LIMIT_FILE_SIZE'
      ? `CV is too large. Maximum size is ${MAX_CV_MB} MB.`
      : error.message || 'Unable to process the request.';
    res.status(400).json({ message });
  }
});

app.use(express.static(PUBLIC_DIR, {
  extensions: ['html'],
  maxAge: process.env.NODE_ENV === 'production' ? '1d' : 0,
  setHeaders: (res, filePath) => {
    if (filePath.endsWith('.html')) res.setHeader('Cache-Control', 'no-cache');
  }
}));
app.use((req, res, next) => {
  if (req.path.startsWith('/api/')) return res.status(404).json({ message: 'Not found.' });
  if (req.method !== 'GET' && req.method !== 'HEAD') return next();
  if (path.extname(req.path)) return res.status(404).type('text/plain').send('Not found');
  res.sendFile(path.join(PUBLIC_DIR, 'index.html'));
});

app.use((err, _req, res, _next) => {
  if (err instanceof multer.MulterError || /^Only PDF/.test(err.message || '')) {
    const big = err.code === 'LIMIT_FILE_SIZE';
    return res.status(big ? 413 : 400).json({ message: big ? `CV is too large. Maximum size is ${MAX_CV_MB} MB.` : (err.message || 'Invalid upload.') });
  }
  console.error(err);
  res.status(500).json({ message: 'An unexpected server error occurred.' });
});

const server = http.createServer(app);
server.listen(PORT, () => {
  console.log(`GSEA server listening on http://localhost:${PORT}`);
  if (!mailConfigured()) console.warn('SMTP is not configured. Forms will be stored, but email notifications are disabled.');
});

function shutdown() {
  db.close();
  server.close(() => process.exit(0));
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
