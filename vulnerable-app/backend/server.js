/**
 * VULNERABLE Express Backend Server (Microservices — MongoDB)
 * =============================================================
 * This server is INTENTIONALLY INSECURE for educational purposes.
 * 
 * Vulnerabilities demonstrated:
 * 1. HTTP only (no TLS/HTTPS) - data transmitted in plaintext
 * 2. No input validation or sanitization
 * 3. No rate limiting
 * 4. No security headers (CSP, HSTS, etc.)
 * 5. Credentials stored in PLAINTEXT in MongoDB
 * 6. No CSRF protection
 * 7. Verbose error messages exposing internal details
 * 8. Database connection string exposed in logs
 * 
 * Architecture: Frontend (React) → Backend (Express) → Database (MongoDB)
 * 
 * MITRE ATT&CK: T1557.002 (ARP Cache Poisoning) enables T1040 (Network Sniffing)
 * OWASP Top 10:2025: A04 (Cryptographic Failures), A02 (Security Misconfiguration)
 */

const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');

const app = express();
const PORT = 5000;

// VULNERABILITY: Database connection string hardcoded and logged
const MONGO_URI = process.env.MONGO_URI || 'mongodb://database:27017/vulnerable_db';
console.log(`[VULNERABLE] Connecting to MongoDB: ${MONGO_URI}`); // VULNERABILITY: Logging connection string

// ===================== MONGODB CONNECTION =====================

mongoose.connect(MONGO_URI)
  .then(() => console.log('[VULNERABLE] Connected to MongoDB — vulnerable_db'))
  .catch(err => {
    console.error('[VULNERABLE] MongoDB connection error:', err.message);
    console.error('[VULNERABLE] Full error:', err); // VULNERABILITY: Verbose error
  });

// ===================== MONGOOSE SCHEMAS =====================

// VULNERABILITY: No validation constraints on schema
const userSchema = new mongoose.Schema({
  username: String,       // No unique constraint, no validation
  password: String,       // PLAINTEXT — no hashing!
  role: String,
  email: String,
  created_at: { type: Date, default: Date.now }
});

// VULNERABILITY: Schema exposes all fields by default (no select: false)
const User = mongoose.model('User', userSchema);

const transactionSchema = new mongoose.Schema({
  from: String,
  to: String,
  amount: Number,         // No min/max validation
  description: String,    // No sanitization
  created_at: { type: Date, default: Date.now }
});

const Transaction = mongoose.model('Transaction', transactionSchema);

// ===================== MIDDLEWARE =====================

// VULNERABILITY: CORS allows all origins
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// ===================== ROUTES =====================

// VULNERABILITY: No rate limiting on login endpoint
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  // VULNERABILITY: No input validation
  // VULNERABILITY: Logging credentials in plaintext
  console.log(`[VULNERABLE] Login attempt - Username: ${username}, Password: ${password}`);

  try {
    // VULNERABILITY: Plaintext password comparison!
    const user = await User.findOne({ username, password });

    if (user) {
      // VULNERABILITY: Simple token without encryption or signing
      const token = Buffer.from(`${user._id}:${user.username}:${Date.now()}`).toString('base64');

      console.log(`[VULNERABLE] Login successful - Token: ${token}`);

      // VULNERABILITY: Sending sensitive data in response (including password!)
      res.json({
        success: true,
        message: 'Login berhasil',
        token: token,
        user: {
          id: user._id,
          username: user.username,
          email: user.email,
          role: user.role,
          password: user.password // VULNERABILITY: Password included in response!
        }
      });
    } else {
      // VULNERABILITY: Verbose error message helps attackers enumerate users
      const userExists = await User.findOne({ username });
      if (userExists) {
        res.status(401).json({
          success: false,
          message: `Password salah untuk user "${username}"`,
          hint: `Password dimulai dengan "${userExists.password.substring(0, 3)}..."` // VULNERABILITY!
        });
      } else {
        res.status(401).json({
          success: false,
          message: `Username "${username}" tidak ditemukan dalam database`
        });
      }
    }
  } catch (err) {
    // VULNERABILITY: Exposing internal error details
    res.status(500).json({
      success: false,
      message: 'Database error',
      error: err.message,
      stack: err.stack // VULNERABILITY: Stack trace exposed!
    });
  }
});

// VULNERABILITY: Unprotected endpoint exposing ALL user data
app.get('/api/users', async (req, res) => {
  console.log('[VULNERABLE] User list accessed without authentication');
  try {
    const users = await User.find({});
    res.json({
      success: true,
      count: users.length,
      database: 'MongoDB (vulnerable_db)',
      users: users.map(u => ({
        id: u._id,
        username: u.username,
        email: u.email,
        role: u.role,
        password: u.password // VULNERABILITY: Passwords exposed!
      }))
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// VULNERABILITY: No authentication required for profile
app.get('/api/profile', async (req, res) => {
  const token = req.headers.authorization;

  if (!token) {
    return res.status(401).json({
      success: false,
      message: 'Token tidak valid'
    });
  }

  try {
    // VULNERABILITY: Decoding Base64 token (not verifying signature)
    const decoded = Buffer.from(token, 'base64').toString();
    const [userId] = decoded.split(':');

    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({ success: false, message: 'User tidak ditemukan' });
    }

    res.json({
      success: true,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        password: user.password // VULNERABILITY: Password in profile response!
      },
      serverInfo: {
        protocol: 'HTTP',
        encrypted: false,
        database: 'MongoDB (vulnerable_db)',
        port: PORT,
        nodeVersion: process.version
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// VULNERABILITY: Transfer endpoint with no security
app.post('/api/transfer', async (req, res) => {
  const { from, to, amount, description } = req.body;

  // VULNERABILITY: Logging sensitive transaction data
  console.log(`[VULNERABLE] Transfer: ${from} -> ${to}, Amount: ${amount}, Desc: ${description}`);

  try {
    // VULNERABILITY: No authentication check, no validation
    const transaction = new Transaction({ from, to, amount, description });
    await transaction.save();

    res.json({
      success: true,
      message: `Transfer Rp ${amount} dari ${from} ke ${to} berhasil`,
      transactionId: transaction._id,
      details: { from, to, amount, description }
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// VULNERABILITY: Unprotected transaction history
app.get('/api/transactions', async (req, res) => {
  try {
    const transactions = await Transaction.find({}).sort({ created_at: -1 });
    res.json({
      success: true,
      count: transactions.length,
      transactions
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Health check
app.get('/api/health', async (req, res) => {
  const dbState = mongoose.connection.readyState;
  const dbStates = { 0: 'disconnected', 1: 'connected', 2: 'connecting', 3: 'disconnecting' };
  
  res.json({
    status: 'running',
    protocol: 'HTTP',
    encrypted: false,
    database: {
      type: 'MongoDB',
      name: 'vulnerable_db',
      status: dbStates[dbState] || 'unknown',
      uri: MONGO_URI // VULNERABILITY: Exposing database URI!
    },
    message: 'WARNING: Server ini berjalan tanpa enkripsi! Data dikirim dalam plaintext.',
    timestamp: new Date().toISOString()
  });
});

// ===================== START SERVER =====================

app.listen(PORT, '0.0.0.0', () => {
  console.log(`
╔══════════════════════════════════════════════════════════════╗
║  ⚠️  VULNERABLE SERVER - FOR EDUCATIONAL PURPOSES ONLY  ⚠️   ║
║                                                              ║
║  Server berjalan di: http://0.0.0.0:${PORT}                   ║
║  Protocol: HTTP (TIDAK TERENKRIPSI)                          ║
║  Database: MongoDB (vulnerable_db) — PLAINTEXT passwords     ║
║  Status: RENTAN terhadap MITM / ARP Spoofing                ║
║                                                              ║
║  MITRE ATT&CK: T1557.002, T1040                             ║
║  OWASP: A04:2025 (Cryptographic Failures)                    ║
╚══════════════════════════════════════════════════════════════╝
  `);
});
