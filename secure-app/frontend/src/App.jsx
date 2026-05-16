import React, { useState } from 'react';
import './App.css';

/**
 * SECURE Frontend Application
 * =============================
 * This React app demonstrates a SECURE login interface with HTTPS.
 * 
 * Security Measures:
 * - Communicates over HTTPS (TLS encrypted)
 * - Client-side input validation
 * - JWT token stored securely
 * - No sensitive data exposed in UI
 * - CSP headers set in HTML
 */

const API_URL = process.env.REACT_APP_API_URL || 'https://localhost:5443';

function App() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [message, setMessage] = useState(null);
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(null);
  const [loading, setLoading] = useState(false);
  const [loginAttempts, setLoginAttempts] = useState(0);

  // Validation state
  const [errors, setErrors] = useState({});

  // Transfer form state
  const [transferTo, setTransferTo] = useState('');
  const [transferAmount, setTransferAmount] = useState('');
  const [transferDesc, setTransferDesc] = useState('');
  const [transferResult, setTransferResult] = useState(null);

  // Client-side validation
  const validateInput = () => {
    const newErrors = {};
    
    if (username.length < 3 || username.length > 30) {
      newErrors.username = 'Username harus 3-30 karakter';
    }
    if (!/^[a-zA-Z0-9_]+$/.test(username)) {
      newErrors.username = 'Username hanya boleh alfanumerik dan underscore';
    }
    if (password.length < 6) {
      newErrors.password = 'Password minimal 6 karakter';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleLogin = async (e) => {
    e.preventDefault();

    // Client-side validation first
    if (!validateInput()) return;

    // Rate limit check on client
    if (loginAttempts >= 5) {
      setMessage({ type: 'error', text: 'Terlalu banyak percobaan. Tunggu beberapa saat.' });
      return;
    }

    setLoading(true);
    setMessage(null);
    setLoginAttempts(prev => prev + 1);

    try {
      // SECURE: Sending over HTTPS - data is encrypted in transit
      const response = await fetch(`${API_URL}/api/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
      });

      const data = await response.json();

      if (data.success) {
        setUser(data.user);
        setToken(data.token);
        // Store token (in production, use httpOnly cookies)
        sessionStorage.setItem('token', data.token);
        setMessage({ type: 'success', text: data.message });
        setLoginAttempts(0);
      } else {
        setMessage({ type: 'error', text: data.message });
      }
    } catch (err) {
      setMessage({ type: 'error', text: 'Koneksi gagal. Pastikan server HTTPS aktif.' });
    }

    setLoading(false);
  };

  const handleTransfer = async (e) => {
    e.preventDefault();

    if (!transferTo || !transferAmount) return;

    try {
      const response = await fetch(`${API_URL}/api/transfer`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          to: transferTo,
          amount: parseFloat(transferAmount),
          description: transferDesc
        })
      });

      const data = await response.json();
      setTransferResult(data);
    } catch (err) {
      setTransferResult({ success: false, message: err.message });
    }
  };

  const handleLogout = () => {
    setUser(null);
    setToken(null);
    setMessage(null);
    setTransferResult(null);
    sessionStorage.removeItem('token');
    setUsername('');
    setPassword('');
  };

  // Generate a fake "encrypted" representation for demo
  const generateEncryptedView = () => {
    const chars = '0123456789abcdef';
    let result = '';
    for (let i = 0; i < 128; i++) {
      result += chars[Math.floor(Math.random() * chars.length)];
      if ((i + 1) % 32 === 0) result += '\n';
      else if ((i + 1) % 2 === 0) result += ' ';
    }
    return result;
  };

  return (
    <div className="app-container">
      {/* Security Banner */}
      <div className="security-banner">
        <span className="icon">🔒</span>
        <div className="text">
          <strong>SECURE APP</strong> — Aplikasi ini menggunakan enkripsi
          <span className="badge">TLS/HTTPS</span>
        </div>
      </div>

      <div className="login-card">
        {/* Logo */}
        <div className="logo">
          <span className="icon">🏦</span>
          <h1>SecureBank</h1>
          <p className="subtitle">Internet Banking Portal (Secure)</p>
        </div>

        {/* Protocol Badge */}
        <div className="protocol-badge">
          <span className="dot"></span>
          <span>HTTPS — TERENKRIPSI TLS 1.2+</span>
        </div>

        {/* Security Features */}
        <div className="security-features">
          <h4>🛡️ Fitur Keamanan Aktif</h4>
          <ul>
            <li>TLS/HTTPS Encryption</li>
            <li>Helmet Security Headers (CSP, HSTS)</li>
            <li>Rate Limiting (5 percobaan / 15 menit)</li>
            <li>Input Validation & Sanitization</li>
            <li>Password Hashing (bcrypt, salt: 12)</li>
            <li>JWT Authentication (1h expiry)</li>
          </ul>
        </div>

        {!user ? (
          /* Login Form */
          <form onSubmit={handleLogin}>
            <div className="form-group">
              <label htmlFor="username">Username</label>
              <input
                id="username"
                type="text"
                placeholder="Masukkan username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
                minLength={3}
                maxLength={30}
                pattern="[a-zA-Z0-9_]+"
              />
              {errors.username && <p className="validation-error">{errors.username}</p>}
              <p className="input-hint">3-30 karakter alfanumerik</p>
            </div>
            <div className="form-group">
              <label htmlFor="password">Password</label>
              <input
                id="password"
                type="password"
                placeholder="Masukkan password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                minLength={6}
                maxLength={128}
              />
              {errors.password && <p className="validation-error">{errors.password}</p>}
              <p className="input-hint">Minimal 6 karakter</p>
            </div>
            <button type="submit" className="btn-login" disabled={loading || loginAttempts >= 5}>
              {loading ? 'Memproses...' : '🔐 Secure Login'}
            </button>
            <div className="rate-limit-info">
              🛡️ Rate limit: {5 - loginAttempts} percobaan tersisa
            </div>
          </form>
        ) : (
          /* Dashboard */
          <>
            <div className="dashboard">
              <h3>👤 Profil Pengguna</h3>
              <div className="info-row">
                <span className="label">Username</span>
                <span className="value">{user.username}</span>
              </div>
              <div className="info-row">
                <span className="label">Role</span>
                <span className="value">{user.role}</span>
              </div>
              <div className="info-row">
                <span className="label">Password</span>
                <span className="value safe">●●●●●●●● (Tidak terekspos)</span>
              </div>
              <div className="info-row">
                <span className="label">Protocol</span>
                <span className="value safe">HTTPS/TLS (Aman)</span>
              </div>
              <div className="info-row">
                <span className="label">Token Type</span>
                <span className="value safe">JWT (1h expiry)</span>
              </div>
            </div>

            {/* Transfer Form */}
            <div className="transfer-section">
              <h3>💸 Transfer Dana (Secure)</h3>
              <form onSubmit={handleTransfer}>
                <div className="form-group">
                  <label>Penerima</label>
                  <input
                    type="text"
                    placeholder="Username penerima"
                    value={transferTo}
                    onChange={(e) => setTransferTo(e.target.value)}
                    required
                    minLength={3}
                    maxLength={30}
                  />
                </div>
                <div className="form-group">
                  <label>Jumlah (Rp)</label>
                  <input
                    type="number"
                    placeholder="100000"
                    value={transferAmount}
                    onChange={(e) => setTransferAmount(e.target.value)}
                    required
                    min={1}
                    max={1000000000}
                  />
                </div>
                <div className="form-group">
                  <label>Keterangan</label>
                  <input
                    type="text"
                    placeholder="Transfer pembayaran"
                    value={transferDesc}
                    onChange={(e) => setTransferDesc(e.target.value)}
                    maxLength={200}
                  />
                </div>
                <button type="submit" className="btn-login">🔐 Kirim Transfer (Encrypted)</button>
              </form>

              {transferResult && (
                <div className={`message ${transferResult.success ? 'success' : 'error'}`}>
                  {transferResult.message}
                </div>
              )}
            </div>

            <button className="btn-logout" onClick={handleLogout}>
              🚪 Logout
            </button>
          </>
        )}

        {message && (
          <div className={`message ${message.type}`}>
            {message.text}
          </div>
        )}
      </div>

      {/* Encrypted Data Display */}
      <div className="encrypted-data">
        <h4>🔐 Data Terenkripsi - Tidak Dapat Dibaca oleh Attacker (HTTPS/TLS)</h4>
        <pre>{`TLS 1.3 Handshake → Encrypted Application Data

Yang dilihat attacker setelah ARP Spoofing:
${generateEncryptedView()}
↑ Data terenkripsi - TIDAK BERGUNA bagi attacker`}</pre>
      </div>

      <div className="footer-info">
        Network Programming & Administration — Tugas Kelompok 5<br />
        MITRE ATT&CK Mitigation: M1041 | OWASP: A04:2025 Compliant
      </div>
    </div>
  );
}

export default App;
