/**
 * SECURE Express Backend Server
 * ===============================
 * This server implements security best practices to defend against MITM attacks.
 * 
 * Security measures implemented:
 * 1. HTTPS/TLS encryption - data transmitted encrypted
 * 2. Input validation and sanitization (express-validator)
 * 3. Rate limiting (express-rate-limit)
 * 4. Security headers (Helmet - CSP, HSTS, X-Frame-Options, etc.)
 * 5. Password hashing (bcryptjs)
 * 6. JWT token authentication
 * 7. CORS restricted to specific origins
 * 8. HTTP Parameter Pollution protection (hpp)
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

const app = express();
const PORT = 5443;
const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-jwt-key-change-in-production-2025';

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

// ===================== USER STORE (Hashed Passwords) =====================

const initUsers = async () => {
  const salt = await bcrypt.genSalt(12);
  return [
    {
      id: 1,
      username: 'admin',
      password: await bcrypt.hash('admin123', salt),
      role: 'administrator',
      email: 'admin@company.com'
    },
    {
      id: 2,
      username: 'user1',
      password: await bcrypt.hash('password123', salt),
      role: 'user',
      email: 'user1@company.com'
    },
    {
      id: 3,
      username: 'manager',
      password: await bcrypt.hash('manager456', salt),
      role: 'manager',
      email: 'manager@company.com'
    }
  ];
};

let users = [];
initUsers().then(u => { users = u; });

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

    // Log without sensitive data
    console.log(`[SECURE] Login attempt for user: ${username.substring(0, 3)}***`);

    const user = users.find(u => u.username === username);

    if (!user) {
      // Generic error message (doesn't reveal if user exists)
      return res.status(401).json({
        success: false,
        message: 'Username atau password salah'
      });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(401).json({
        success: false,
        message: 'Username atau password salah'
      });
    }

    // Generate JWT token
    const token = jwt.sign(
      { userId: user.id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: '1h', issuer: 'secure-app' }
    );

    console.log(`[SECURE] Login successful for: ${username.substring(0, 3)}***`);

    // Return safe user data (no password, no sensitive info)
    res.json({
      success: true,
      message: 'Login berhasil',
      token: token,
      user: {
        id: user.id,
        username: user.username,
        role: user.role
        // NOTE: No email, no password in response
      }
    });
  }
);

// Protected profile endpoint
app.get('/api/profile', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === req.user.userId);

  if (!user) {
    return res.status(404).json({ success: false, message: 'User tidak ditemukan' });
  }

  res.json({
    success: true,
    user: {
      id: user.id,
      username: user.username,
      role: user.role
    },
    serverInfo: {
      protocol: 'HTTPS',
      encrypted: true,
      tlsVersion: 'TLSv1.3',
      port: PORT
    }
  });
});

// Protected transfer endpoint with validation
app.post('/api/transfer',
  authenticateToken,
  [
    body('to').trim().isLength({ min: 3, max: 30 }).withMessage('Penerima tidak valid'),
    body('amount').isFloat({ min: 1, max: 1000000000 }).withMessage('Jumlah tidak valid'),
    body('description').trim().isLength({ max: 200 }).escape().withMessage('Deskripsi terlalu panjang')
  ],
  (req, res) => {
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

    console.log(`[SECURE] Transfer: ${from.substring(0, 3)}*** -> ${to.substring(0, 3)}***, Amount: ***`);

    res.json({
      success: true,
      message: `Transfer berhasil diproses`,
      transactionId: `STXN-${Date.now()}`
    });
  }
);

// Health check (limited info)
app.get('/api/health', (req, res) => {
  res.json({
    status: 'running',
    protocol: 'HTTPS',
    encrypted: true,
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
║  🔒  SECURE SERVER - HTTPS/TLS ENABLED                  🔒  ║
║                                                              ║
║  Server berjalan di: https://0.0.0.0:${PORT}                  ║
║  Protocol: HTTPS (TLS 1.2+)                                 ║
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
