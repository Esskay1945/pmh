const express = require('express');
const { nanoid } = require('nanoid');
const path = require('path');
const fs = require('fs');
const cors = require('cors');
const helmet = require('helmet');
const multer = require('multer');
const rateLimit = require('express-rate-limit');
const { body, query, validationResult } = require('express-validator');
const xss = require('xss-clean');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// --- STORAGE & UPLOADS SETUP ---
const UPLOADS_DIR = path.join(__dirname, 'public', 'uploads');
if (!fs.existsSync(UPLOADS_DIR)) {
  fs.mkdirSync(UPLOADS_DIR, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS_DIR),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, `${nanoid(10)}${ext}`);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('audio/')) cb(null, true);
    else cb(new Error('Only audio files are allowed!'), false);
  }
});

// In-memory buckets
const users = new Map(); // email -> {password, id}
const links = new Map(); // id -> inviteData
const sessions = new Map(); // sessionId -> {userId, email}

// --- MIDDLEWARE ---

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '10kb' }));
app.use(xss());
app.use(cors());
app.use(express.static('public'));

const validate = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ error: 'Validation failed', details: errors.array() });
  next();
};

const auth = (req, res, next) => {
  const sessionId = req.headers['authorization'];
  const session = sessions.get(sessionId);
  if (session) {
    req.user = session;
    next();
  } else {
    res.status(401).json({ error: 'Unauthorized' });
  }
};

// --- AUTH API ---

app.post('/api/register', [
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 6 })
], validate, (req, res) => {
  const { email, password } = req.body;
  if (users.has(email)) return res.status(400).json({ error: 'User already exists' });

  const userId = nanoid();
  users.set(email, { password, id: userId });
  res.json({ success: true, message: 'Welcome to the club! 💕' });
});

app.post('/api/login', [
  body('email').isEmail().normalizeEmail(),
  body('password').isString().notEmpty()
], validate, (req, res) => {
  const { email, password } = req.body;
  const user = users.get(email);
  if (user && user.password === password) {
    const sessionId = nanoid(32);
    sessions.set(sessionId, { userId: user.id, email });
    res.json({ success: true, sessionId });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

// --- INVITE API ---

app.post('/api/upload-audio', auth, upload.single('audio'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  res.json({ success: true, filename: req.file.filename });
});

app.post('/api/generate-link', auth, [
  body('name').isString().trim().notEmpty().escape(),
  body('message').optional().isString().trim().escape(),
  body('audioFile').optional().isString()
], validate, async (req, res) => {
  const { name, message, audioFile } = req.body;
  const linkId = nanoid(10);

  links.set(linkId, {
    ownerId: req.user.userId,
    name,
    message: message || '',
    audioPath: audioFile ? `/uploads/${audioFile}` : '',
    status: 'pending',
    createdAt: new Date()
  });

  res.json({ linkId });
});

app.get('/api/invites', auth, (req, res) => {
  const userInvites = Array.from(links.entries())
    .filter(([id, data]) => data.ownerId === req.user.userId)
    .map(([id, data]) => ({ id, ...data }))
    .sort((a, b) => b.createdAt - a.createdAt);
  res.json(userInvites);
});

// For Invitee
app.get('/api/get-link', [query('id').isLength({ min: 10, max: 10 })], validate, (req, res) => {
  const linkData = links.get(req.query.id);
  if (!linkData) return res.status(404).json({ error: 'Lost heart... 💔' });
  res.json({
    name: linkData.name,
    message: linkData.message,
    audioUrl: linkData.audioPath,
    status: linkData.status
  });
});

app.post('/api/respond', [
  body('linkId').isLength({ min: 10, max: 10 }),
  body('response').isIn(['yes', 'no'])
], validate, (req, res) => {
  const { linkId, response } = req.body;
  const linkData = links.get(linkId);
  if (!linkData) return res.status(404).json({ error: 'Lost heart... 💔' });

  linkData.status = response === 'yes' ? 'accepted' : 'rejected';
  linkData.respondedAt = new Date();
  res.json({ success: true });
});

// --- SERVE HTML ---
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/register', (req, res) => res.sendFile(path.join(__dirname, 'public', 'register.html')));
app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'public', 'dashboard.html')));
app.get('/date.html', (req, res) => res.sendFile(path.join(__dirname, 'public', 'date.html')));

app.listen(PORT, () => console.log(`🚀 Server heart beating at http://localhost:${PORT}`));


