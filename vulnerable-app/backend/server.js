/**
 * VULNERABLE Express Backend Server
 * ===================================
 * This server is INTENTIONALLY INSECURE for educational purposes.
 * 
 * Vulnerabilities demonstrated:
 * 1. HTTP only (no TLS/HTTPS) - data transmitted in plaintext
 * 2. No input validation or sanitization
 * 3. No rate limiting
 * 4. No security headers (CSP, HSTS, etc.)
 * 5. Credentials stored in plaintext
 * 6. No CSRF protection
 * 7. Verbose error messages exposing internal details
 * 
 * MITRE ATT&CK: T1557.002 (ARP Cache Poisoning) enables T1040 (Network Sniffing)
 * OWASP Top 10:2025: A04 (Cryptographic Failures), A02 (Security Misconfiguration)
 */

const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');

const app = express();
const PORT = 5000;

// VULNERABILITY: CORS allows all origins
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// VULNERABILITY: In-memory user store with plaintext passwords
const users = [
  { id: 1, username: 'admin', password: 'admin123', role: 'administrator', email: 'admin@company.com' },
  { id: 2, username: 'user1', password: 'password123', role: 'user', email: 'user1@company.com' },
  { id: 3, username: 'manager', password: 'manager456', role: 'manager', email: 'manager@company.com' }
];

// Session store (in-memory, no encryption)
const sessions = {};

// VULNERABILITY: No rate limiting on login endpoint
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;

  // VULNERABILITY: No input validation
  console.log(`[VULNERABLE] Login attempt - Username: ${username}, Password: ${password}`);

  const user = users.find(u => u.username === username && u.password === password);

  if (user) {
    // VULNERABILITY: Simple token without encryption
    const token = Buffer.from(`${user.id}:${user.username}:${Date.now()}`).toString('base64');
    sessions[token] = { userId: user.id, username: user.username };

    console.log(`[VULNERABLE] Login successful - Token: ${token}`);

    // VULNERABILITY: Sending sensitive data in response
    res.json({
      success: true,
      message: 'Login berhasil',
      token: token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
        password: user.password // VULNERABILITY: Password included in response!
      }
    });
  } else {
    // VULNERABILITY: Verbose error message helps attackers
    const userExists = users.find(u => u.username === username);
    if (userExists) {
      res.status(401).json({
        success: false,
        message: `Password salah untuk user "${username}"`,
        hint: `Password dimulai dengan "${userExists.password.substring(0, 3)}..."`
      });
    } else {
      res.status(401).json({
        success: false,
        message: `Username "${username}" tidak ditemukan dalam database`
      });
    }
  }
});

// VULNERABILITY: Unprotected endpoint exposing user data
app.get('/api/users', (req, res) => {
  console.log('[VULNERABLE] User list accessed without authentication');
  res.json({
    success: true,
    users: users.map(u => ({
      id: u.id,
      username: u.username,
      email: u.email,
      role: u.role,
      password: u.password // VULNERABILITY: Passwords exposed!
    }))
  });
});

// VULNERABILITY: Session data accessible without proper auth
app.get('/api/profile', (req, res) => {
  const token = req.headers.authorization;

  if (!token || !sessions[token]) {
    return res.status(401).json({
      success: false,
      message: 'Token tidak valid',
      activeSessions: Object.keys(sessions).length // VULNERABILITY: Exposing session count
    });
  }

  const session = sessions[token];
  const user = users.find(u => u.id === session.userId);

  res.json({
    success: true,
    user: user,
    serverInfo: {
      protocol: 'HTTP',
      encrypted: false,
      port: PORT,
      nodeVersion: process.version
    }
  });
});

// VULNERABILITY: Transfer endpoint with no security
app.post('/api/transfer', (req, res) => {
  const { from, to, amount, description } = req.body;

  console.log(`[VULNERABLE] Transfer: ${from} -> ${to}, Amount: ${amount}, Desc: ${description}`);

  res.json({
    success: true,
    message: `Transfer Rp ${amount} dari ${from} ke ${to} berhasil`,
    transactionId: `TXN-${Date.now()}`,
    details: { from, to, amount, description }
  });
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({
    status: 'running',
    protocol: 'HTTP',
    encrypted: false,
    message: 'WARNING: Server ini berjalan tanpa enkripsi! Data dikirim dalam plaintext.',
    timestamp: new Date().toISOString()
  });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`
╔══════════════════════════════════════════════════════════════╗
║  ⚠️  VULNERABLE SERVER - FOR EDUCATIONAL PURPOSES ONLY  ⚠️   ║
║                                                              ║
║  Server berjalan di: http://0.0.0.0:${PORT}                   ║
║  Protocol: HTTP (TIDAK TERENKRIPSI)                          ║
║  Status: RENTAN terhadap MITM / ARP Spoofing                ║
║                                                              ║
║  MITRE ATT&CK: T1557.002, T1040                             ║
║  OWASP: A04:2025 (Cryptographic Failures)                    ║
╚══════════════════════════════════════════════════════════════╝
  `);
});
