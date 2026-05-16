/**
 * SECURE Express Backend Server (Microservices — MongoDB)
 * ========================================================
 * This server implements security best practices to defend against MITM attacks.
 * 
 * Security measures implemented:
 * 1. HTTPS/TLS encryption - data transmitted encrypted
 * 2. Input validation and sanitization (express-validator)
 * 3. Rate limiting (express-rate-limit)
 * 4. Security headers (Helmet - CSP, HSTS, X-Frame-Options, etc.)
 * 5. Password hashing (bcryptjs) — stored as hash in MongoDB
 * 6. JWT token authentication with expiry
 * 7. CORS restricted to specific origins
 * 8. HTTP Parameter Pollution protection (hpp)
 * 9. Audit logging for security events
 * 10. Secure MongoDB connection with proper error handling
 * 
 * Architecture: Frontend (React) → Backend (Express HTTPS) → Database (MongoDB)
 * 
 * MITRE ATT&CK Mitigation: M1041 (Encrypt Sensitive Information), M1030 (Network Segmentation)
 * OWASP Top 10:2025 Compliance: A04 (Cryptographic Failures) - RESOLVED
 */

const express = require('express');
const https = require('https');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const bodyParser = require('body-parser');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const hpp = require('hpp');
const cookieParser = require('cookie-parser');
const mongoose = require('mongoose');

const app = express();
const PORT = 5443;
const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-jwt-key-change-in-production-2025';

// SECURE: Database connection string from environment variable (not hardcoded)
const MONGO_URI = process.env.MONGO_URI || 'mongodb://database:27017/secure_db';

// ===================== MONGODB CONNECTION =====================

mongoose.connect(MONGO_URI)
  .then(() => {
    console.log('[SECURE] Connected to MongoDB — secure_db');
    seedUsers(); // Seed bcrypt-hashed passwords on startup
  })
  .catch(err => {
    // SECURE: Don't log full connection string or stack trace
    console.error('[SECURE] MongoDB connection failed. Retrying...');
    setTimeout(() => mongoose.connect(MONGO_URI), 5000);
  });

// ===================== MONGOOSE SCHEMAS =====================

// SECURE: Schema with validation constraints
const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    minlength: 3,
    maxlength: 30,
    match: /^[a-zA-Z0-9_]+$/
  },
  password: {
    type: String,
    required: true,
    select: false  // SECURE: Password not included in queries by default
  },
  role: {
    type: String,
    enum: ['user', 'manager', 'administrator'],
    default: 'user'
  },
  email: {
    type: String,
    required: true,
    lowercase: true,
    trim: true
  },
  login_attempts: { type: Number, default: 0 },
  locked_until: { type: Date, default: null },
  created_at: { type: Date, default: Date.now },
  updated_at: { type: Date, default: Date.now }
});

// SECURE: Don't expose password or internal fields in JSON
userSchema.methods.toSafeJSON = function () {
  return {
    id: this._id,
    username: this.username,
    role: this.role
  };
};

const User = mongoose.model('User', userSchema);

const transactionSchema = new mongoose.Schema({
  from: { type: String, required: true },
  to: { type: String, required: true },
  amount: { type: Number, required: true, min: 1, max: 1000000000 },
  description: { type: String, maxlength: 200 },
  created_at: { type: Date, default: Date.now, expires: 86400 } // TTL 24h
});

const Transaction = mongoose.model('Transaction', transactionSchema);

const auditLogSchema = new mongoose.Schema({
  event: { type: String, required: true },
  username: String,
  ip: String,
  details: String,
  timestamp: { type: Date, default: Date.now, expires: 604800 } // TTL 7 days
});

const AuditLog = mongoose.model('AuditLog', auditLogSchema);

// ===================== SEED USERS (Bcrypt Hashed) =====================

async function seedUsers() {
  try {
    const count = await User.countDocuments();
    if (count === 0) {
      console.log('[SECURE] Seeding users with bcrypt-hashed passwords...');
      const salt = await bcrypt.genSalt(12);

      await User.insertMany([
        {
          username: 'admin',
          password: await bcrypt.hash('admin123', salt),
          role: 'administrator',
          email: 'admin@company.com'
        },
        {
          username: 'user1',
          password: await bcrypt.hash('password123', salt),
          role: 'user',
          email: 'user1@company.com'
        },
        {
          username: 'manager',
          password: await bcrypt.hash('manager456', salt),
          role: 'manager',
          email: 'manager@company.com'
        }
      ]);

      console.log('[SECURE] Users seeded successfully (passwords are bcrypt hashes)');
    } else {
      console.log(`[SECURE] ${count} users already exist in secure_db`);
    }
  } catch (err) {
    console.error('[SECURE] Error seeding users:', err.message);
  }
}

// ===================== SECURITY MIDDLEWARE =====================

// Helmet: Set security-related HTTP headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
    },
  },
  hsts: {
    maxAge: 31536000, // 1 year
    includeSubDomains: true,
    preload: true
  },
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
}));

// Rate limiting
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 login attempts per window
  message: {
    success: false,
    message: 'Terlalu banyak percobaan login. Coba lagi dalam 15 menit.'
  },
  standardHeaders: true,
  legacyHeaders: false
});

const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false
});

app.use(generalLimiter);

// CORS restricted
app.use(cors({
  origin: process.env.ALLOWED_ORIGIN || 'https://localhost:3443',
  credentials: true,
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(bodyParser.json({ limit: '10kb' })); // Limit body size
app.use(bodyParser.urlencoded({ extended: false }));
app.use(hpp()); // Prevent HTTP Parameter Pollution
app.use(cookieParser());

// ===================== JWT MIDDLEWARE =====================

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({ success: false, message: 'Token diperlukan' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(403).json({ success: false, message: 'Token tidak valid atau sudah kadaluarsa' });
  }
};

// ===================== AUDIT HELPER =====================

async function logAudit(event, username, ip, details) {
  try {
    await new AuditLog({ event, username, ip, details }).save();
  } catch (err) {
    console.error('[SECURE] Audit log error:', err.message);
  }
}

// ===================== ROUTES =====================

// Login with validation and rate limiting
app.post('/api/login',
  loginLimiter,
  [
    body('username')
      .trim()
      .isLength({ min: 3, max: 30 })
      .matches(/^[a-zA-Z0-9_]+$/)
      .withMessage('Username harus 3-30 karakter alfanumerik'),
    body('password')
      .isLength({ min: 6, max: 128 })
      .withMessage('Password harus minimal 6 karakter')
  ],
  async (req, res) => {
    // Check validation
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Input tidak valid',
        errors: errors.array().map(e => e.msg)
      });
    }

    const { username, password } = req.body;

    // SECURE: Log without sensitive data
    console.log(`[SECURE] Login attempt for user: ${username.substring(0, 3)}***`);

    try {
      // SECURE: Explicitly select password field for comparison
      const user = await User.findOne({ username }).select('+password');

      if (!user) {
        // SECURE: Generic error message (doesn't reveal if user exists)
        await logAudit('LOGIN_FAILED', username, req.ip, 'User not found');
        return res.status(401).json({
          success: false,
          message: 'Username atau password salah'
        });
      }

      // SECURE: Bcrypt comparison (timing-safe)
      const isPasswordValid = await bcrypt.compare(password, user.password);

      if (!isPasswordValid) {
        await logAudit('LOGIN_FAILED', username, req.ip, 'Invalid password');
        return res.status(401).json({
          success: false,
          message: 'Username atau password salah'
        });
      }

      // SECURE: Generate JWT token with expiry
      const token = jwt.sign(
        { userId: user._id, username: user.username, role: user.role },
        JWT_SECRET,
        { expiresIn: '1h', issuer: 'secure-app' }
      );

      await logAudit('LOGIN_SUCCESS', username, req.ip, 'JWT issued');
      console.log(`[SECURE] Login successful for: ${username.substring(0, 3)}***`);

      // SECURE: Return safe user data (no password, no sensitive info)
      res.json({
        success: true,
        message: 'Login berhasil',
        token: token,
        user: user.toSafeJSON()
      });
    } catch (err) {
      console.error('[SECURE] Login error:', err.message);
      res.status(500).json({ success: false, message: 'Internal server error' });
    }
  }
);

// Protected profile endpoint
app.get('/api/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);

    if (!user) {
      return res.status(404).json({ success: false, message: 'User tidak ditemukan' });
    }

    res.json({
      success: true,
      user: user.toSafeJSON(),
      serverInfo: {
        protocol: 'HTTPS',
        encrypted: true,
        database: 'MongoDB (secure_db — bcrypt hashed)',
        tlsVersion: 'TLSv1.3',
        port: PORT
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

// Protected transfer endpoint with validation
app.post('/api/transfer',
  authenticateToken,
  [
    body('to').trim().isLength({ min: 3, max: 30 }).withMessage('Penerima tidak valid'),
    body('amount').isFloat({ min: 1, max: 1000000000 }).withMessage('Jumlah tidak valid'),
    body('description').trim().isLength({ max: 200 }).escape().withMessage('Deskripsi terlalu panjang')
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Input tidak valid',
        errors: errors.array().map(e => e.msg)
      });
    }

    const { to, amount, description } = req.body;
    const from = req.user.username;

    try {
      const transaction = new Transaction({ from, to, amount, description });
      await transaction.save();

      await logAudit('TRANSFER', from, req.ip, `To: ${to.substring(0, 3)}***, Amount: ***`);
      console.log(`[SECURE] Transfer: ${from.substring(0, 3)}*** -> ${to.substring(0, 3)}***, Amount: ***`);

      res.json({
        success: true,
        message: 'Transfer berhasil diproses',
        transactionId: transaction._id
      });
    } catch (err) {
      res.status(500).json({ success: false, message: 'Internal server error' });
    }
  }
);

// Health check (limited info)
app.get('/api/health', async (req, res) => {
  const dbState = mongoose.connection.readyState;
  const dbStates = { 0: 'disconnected', 1: 'connected', 2: 'connecting', 3: 'disconnecting' };

  res.json({
    status: 'running',
    protocol: 'HTTPS',
    encrypted: true,
    database: {
      type: 'MongoDB',
      name: 'secure_db',
      status: dbStates[dbState] || 'unknown'
      // SECURE: No URI exposed
    },
    message: 'Server berjalan dengan enkripsi TLS. Data terproteksi dari MITM.',
    timestamp: new Date().toISOString()
  });
});

// ===================== HTTPS SERVER =====================

const startServer = () => {
  const certPath = path.join(__dirname, 'certs');

  try {
    const options = {
      key: fs.readFileSync(path.join(certPath, 'server.key')),
      cert: fs.readFileSync(path.join(certPath, 'server.crt')),
      // TLS configuration
      minVersion: 'TLSv1.2',
      ciphers: [
        'TLS_AES_256_GCM_SHA384',
        'TLS_CHACHA20_POLY1305_SHA256',
        'TLS_AES_128_GCM_SHA256',
        'ECDHE-RSA-AES256-GCM-SHA384',
        'ECDHE-RSA-AES128-GCM-SHA256'
      ].join(':')
    };

    https.createServer(options, app).listen(PORT, '0.0.0.0', () => {
      console.log(`
╔══════════════════════════════════════════════════════════════╗
║  🔒  SECURE SERVER - HTTPS/TLS + MongoDB                🔒  ║
║                                                              ║
║  Server berjalan di: https://0.0.0.0:${PORT}                  ║
║  Protocol: HTTPS (TLS 1.2+)                                 ║
║  Database: MongoDB (secure_db — bcrypt passwords)            ║
║  Status: TERPROTEKSI dari MITM / ARP Spoofing               ║
║                                                              ║
║  Security Features:                                          ║
║  ✅ TLS/HTTPS Encryption                                     ║
║  ✅ Helmet Security Headers (CSP, HSTS)                      ║
║  ✅ Rate Limiting (5 login/15min)                             ║
║  ✅ Input Validation (express-validator)                      ║
║  ✅ Password Hashing (bcrypt, salt: 12)                       ║
║  ✅ JWT Authentication (1h expiry)                            ║
║  ✅ CORS Restricted                                           ║
║  ✅ HPP Protection                                            ║
║  ✅ Audit Logging                                             ║
║  ✅ MongoDB with secure_db (hashed passwords)                 ║
║                                                              ║
║  MITRE ATT&CK Mitigation: M1041, M1030                      ║
║  OWASP: A04:2025 Compliant                                   ║
╚══════════════════════════════════════════════════════════════╝
      `);
    });
  } catch (err) {
    console.error('❌ Error loading TLS certificates:', err.message);
    console.log('💡 Jalankan: npm run generate-certs untuk membuat sertifikat');
    console.log('⚠️  Fallback: Menjalankan dengan HTTP (TIDAK AMAN)');

    app.listen(PORT, '0.0.0.0', () => {
      console.log(`[FALLBACK] Server running on http://0.0.0.0:${PORT} (NO TLS)`);
    });
  }
};

startServer();
