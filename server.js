// server.js
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use(express.static(__dirname));

// ====== Config ======
const PORT = process.env.PORT || 5000;
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET || (process.env.NODE_ENV !== 'production' ? 'dev-only-change-me' : null);

// ====== Connect DB ======
mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('✅ MongoDB connected'))
  .catch(err => console.error(err));

// ====== User Schema ======
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true },
  passwordHash: String,
  email: String,
  level: { type: Number, default: 1 },
  xp: { type: Number, default: 0 },
  stats: {
    intelligence: { type: Number, default: 50 },
    focus: { type: Number, default: 50 },
    stamina: { type: Number, default: 50 },
    strategy: { type: Number, default: 50 },
    willpower: { type: Number, default: 50 },
    mentalClutter: { type: Number, default: 50 }
  }
});
const User = mongoose.model('User', userSchema);

// ====== Helper: sign JWT ======
function createToken(user) {
  return jwt.sign(
    { id: user._id, username: user.username },
    JWT_SECRET,
    { expiresIn: '1h' } // 1 hour
  );
}

// ====== Middleware: verify JWT ======
function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ success: false, message: 'No token' });

  const token = auth.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ success: false, message: 'Invalid/expired token' });
  }
}

// ====== Routes ======
app.post('/api/register', async (req, res) => {
  const { username, password, email } = req.body;
  if (!username || !password) return res.json({ success: false, message: 'Missing fields' });

  const exists = await User.findOne({ username });
  if (exists) return res.json({ success: false, message: 'User already exists' });

  const hash = await bcrypt.hash(password, 10);
  const user = new User({ username, passwordHash: hash, email });
  await user.save();

  const token = createToken(user);
  res.json({ success: true, token, message: 'Registered successfully' });
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (!user) return res.json({ success: false, message: 'Invalid credentials' });

  const valid = await bcrypt.compare(password, user.passwordHash);
  if (!valid) return res.json({ success: false, message: 'Invalid credentials' });

  const token = createToken(user);
  res.json({ success: true, token, message: 'Login successful' });
});

// Protected route example
app.get('/api/me', authMiddleware, async (req, res) => {
  const user = await User.findById(req.user.id).select('-passwordHash');
  res.json({ success: true, user });
});

// Start server
if (require.main === module) {
  app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
}

module.exports = app;
