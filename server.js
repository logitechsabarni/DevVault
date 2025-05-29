require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL || "postgres://postgres:postgres@localhost:5432/devvault"
});

const JWT_SECRET = process.env.JWT_SECRET || "devvault_jwt_secret";

// AES-256 encryption setup
const ENC_KEY = crypto.createHash('sha256').update(String(process.env.ENC_KEY || 'devvaultencryptionkey')).digest(); // 32 bytes key
const IV = Buffer.alloc(16, 0); // Initialization vector (must be 16 bytes)

// Encryption
function encrypt(text) {
  const cipher = crypto.createCipheriv('aes-256-cbc', ENC_KEY, IV);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
}

// Decryption
function decrypt(encText) {
  const decipher = crypto.createDecipheriv('aes-256-cbc', ENC_KEY, IV);
  let decrypted = decipher.update(encText, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

// Middleware to authenticate JWT token
function auth(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.split(' ')[1];
  if (!token) return res.status(401).send('No token provided');

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(403).send('Invalid token');
  }
}

// User registration
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).send('Missing username or password');
  
  try {
    const hashed = await bcrypt.hash(password, 10);
    await pool.query('INSERT INTO users (username, password) VALUES ($1, $2)', [username, hashed]);
    res.send('User registered');
  } catch (e) {
    if (e.code === '23505') // unique violation
      return res.status(400).send('Username already exists');
    console.error(e);
    res.status(500).send('Server error');
  }
});

// User login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).send('Missing username or password');

  try {
    const result = await pool.query('SELECT * FROM users WHERE username=$1', [username]);
    if (result.rows.length === 0) return res.status(401).send('Invalid credentials');
    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).send('Invalid credentials');

    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '2h' });
    res.json({ token });
  } catch (e) {
    console.error(e);
    res.status(500).send('Server error');
  }
});

// Save secret
app.post('/secret', auth, async (req, res) => {
  const { label, value } = req.body;
  if (!label || !value) return res.status(400).send('Missing label or value');

  try {
    const encrypted = encrypt(value);
    await pool.query('INSERT INTO secrets (user_id, label, value) VALUES ($1, $2, $3)', [req.user.id, label, encrypted]);
    res.send('Secret saved');
  } catch (e) {
    console.error(e);
    res.status(500).send('Error saving secret');
  }
});

// Get secrets
app.get('/secrets', auth, async (req, res) => {
  try {
    const result = await pool.query('SELECT label, value FROM secrets WHERE user_id = $1', [req.user.id]);
    const decrypted = result.rows.map(row => ({ label: row.label, value: decrypt(row.value) }));
    res.json(decrypted);
  } catch (e) {
    console.error(e);
    res.status(500).send('Error fetching secrets');
  }
});

// GitHub webhook for secret detection
app.post('/webhook', express.json({ type: '*/*' }), (req, res) => {
  const { commits } = req.body;
  const secretRegex = /(api[-_]?key|secret|token)[^\s'"]{5,}/gi;
  let exposed = [];

  if (commits) {
    commits.forEach(commit => {
      const combined = commit.message + (commit.added?.join(' ') || '') + (commit.modified?.join(' ') || '');
      const matches = combined.match(secretRegex);
      if (matches) exposed.push({ commitId: commit.id, matches });
    });
  }

  if (exposed.length > 0) {
    console.warn('Potential secrets leaked in commits:', JSON.stringify(exposed, null, 2));
  }
  res.send('Webhook processed');
});

// Import secrets from .env format text
app.post('/import-env', auth, async (req, res) => {
  const { envText } = req.body;
  if (!envText) return res.status(400).send('Missing envText');

  const lines = envText.split('\n').filter(line => line.includes('='));
  try {
    for (const line of lines) {
      const [label, ...vals] = line.split('=');
      const value = vals.join('=').trim();
      if (label && value) {
        const encrypted = encrypt(value);
        await pool.query('INSERT INTO secrets (user_id, label, value) VALUES ($1, $2, $3)', [req.user.id, label.trim(), encrypted]);
      }
    }
    res.send('Imported secrets from env');
  } catch (e) {
    console.error(e);
    res.status(500).send('Import failed');
  }
});

// Start server
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`DevVault backend listening on port ${PORT}`));
