const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ==================== DATABASE ====================
const MONGO_URL = process.env.MONGO_URL || 'mongodb+srv://Niksa1312:nkdo4tFLgV3dWpQA@cluster0.siexgll.mongodb.net/email-service?retryWrites=true&w=majority';

mongoose.connect(MONGO_URL, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => {
  console.log('✅ MongoDB POVEZAN!');
}).catch((err) => {
  console.error('❌ MongoDB GREŠKA:', err);
});

// ==================== SCHEMAS ====================

// User Schema
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

// Inbox Schema
const inboxSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  inboxName: { type: String, required: true },
  emailAddress: { type: String, required: true, unique: true },
  createdAt: { type: Date, default: Date.now }
});

const Inbox = mongoose.model('Inbox', inboxSchema);

// Email Schema
const emailSchema = new mongoose.Schema({
  inboxId: { type: mongoose.Schema.Types.ObjectId, ref: 'Inbox', required: true },
  from: String,
  to: String,
  subject: String,
  text: String,
  html: String,
  timestamp: { type: Date, default: Date.now }
});

const Email = mongoose.model('Email', emailSchema);

// ==================== AUTH ROUTES ====================

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ error: 'Sva polja su obavezna' });
    }

    let user = await User.findOne({ $or: [{ email }, { username }] });
    if (user) return res.status(400).json({ error: 'Korisnik već postoji' });

    const hashedPassword = await bcrypt.hash(password, 10);

    user = new User({
      username,
      email,
      password: hashedPassword
    });

    await user.save();

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET || 'secret123', {
      expiresIn: '7d'
    });

    res.json({ token, user: { id: user._id, username, email } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email i lozinka su obavezni' });
    }

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: 'Korisnik ne postoji' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: 'Pogrešna lozinka' });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET || 'secret123', {
      expiresIn: '7d'
    });

    res.json({ token, user: { id: user._id, username: user.username, email } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==================== MIDDLEWARE ====================

const authMiddleware = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Nema tokena' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret123');
    req.userId = decoded.id;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Neispravan token' });
  }
};

// ==================== INBOX ROUTES ====================

// Kreiraj novi inbox
app.post('/api/inbox/create', authMiddleware, async (req, res) => {
  try {
    const { inboxName } = req.body;

    if (!inboxName) {
      return res.status(400).json({ error: 'Inbox naziv je obavezan' });
    }

    let inbox = await Inbox.findOne({ userId: req.userId, inboxName });
    if (inbox) return res.status(400).json({ error: 'Inbox već postoji' });

    const emailAddress = `${inboxName}@exxqes.xyz`;

    inbox = new Inbox({
      userId: req.userId,
      inboxName,
      emailAddress
    });

    await inbox.save();
    res.json(inbox);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Dohvati sve inboxe korisnika
app.get('/api/inbox/list', authMiddleware, async (req, res) => {
  try {
    const inboxes = await Inbox.find({ userId: req.userId }).sort({ createdAt: -1 });
    res.json(inboxes);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Obriši inbox
app.delete('/api/inbox/:inboxId', authMiddleware, async (req, res) => {
  try {
    const inbox = await Inbox.findById(req.params.inboxId);
    if (!inbox || inbox.userId.toString() !== req.userId.toString()) {
      return res.status(403).json({ error: 'Nemate pristup' });
    }

    await Inbox.deleteOne({ _id: req.params.inboxId });
    await Email.deleteMany({ inboxId: req.params.inboxId });
    res.json({ message: 'Inbox obrisan' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==================== EMAIL ROUTES ====================

// Dohvati mailove za inbox
app.get('/api/emails/:inboxId', authMiddleware, async (req, res) => {
  try {
    const inbox = await Inbox.findById(req.params.inboxId);
    if (!inbox || inbox.userId.toString() !== req.userId.toString()) {
      return res.status(403).json({ error: 'Nemate pristup' });
    }

    const emails = await Email.find({ inboxId: req.params.inboxId }).sort({ timestamp: -1 });
    res.json(emails);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Webhook od Sendgrid-a - primanje emaila
app.post('/api/webhook/email', async (req, res) => {
  try {
    const { to, from, subject, text, html } = req.body;

    if (!to) {
      return res.status(400).json({ error: 'Email adresa je obavezna' });
    }

    const inbox = await Inbox.findOne({ emailAddress: to });
    if (!inbox) {
      console.log(`Inbox nije pronađen za: ${to}`);
      return res.status(404).json({ error: 'Inbox ne postoji' });
    }

    const email = new Email({
      inboxId: inbox._id,
      from: from || 'unknown@unknown.com',
      to,
      subject: subject || '(bez naslova)',
      text: text || '',
      html: html || ''
    });

    await email.save();
    console.log(`✅ Email primljen: ${from} -> ${to}`);
    res.sendStatus(200);
  } catch (err) {
    console.error('❌ Greška pri primanju emaila:', err);
    res.sendStatus(500);
  }
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', message: 'Server je pokrenut!' });
});

// ==================== SERVER ====================

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server pokrenut na portu ${PORT}`);
  console.log(`📧 Email webhook na: /api/webhook/email`);
});
