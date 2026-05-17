import React, { useState } from 'react';
import './App.css';

/**
 * VULNERABLE Frontend Application
 * ================================
 * This React app demonstrates an INSECURE login interface.
 * 
 * Vulnerabilities:
 * - Communicates over HTTP (plaintext)
 * - No input sanitization on client side
 * - Stores token in localStorage (XSS vulnerable)
 * - Displays sensitive data from server responses
 * - No CSRF protection
 */

const API_URL = process.env.REACT_APP_API_URL || 'http://vuln-backend:5000';

function App() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [message, setMessage] = useState(null);
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(null);
  const [loading, setLoading] = useState(false);
  const [lastRequest, setLastRequest] = useState(null);

  // Transfer form state
  const [transferTo, setTransferTo] = useState('');
  const [transferAmount, setTransferAmount] = useState('');
  const [transferDesc, setTransferDesc] = useState('');
  const [transferResult, setTransferResult] = useState(null);

  const handleLogin = async (e) => {
    e.preventDefault();
    setLoading(true);
    setMessage(null);

    // VULNERABILITY: Sending credentials over HTTP plaintext
    const requestBody = JSON.stringify({ username, password });

    // Show what's being sent (for educational demo)
    setLastRequest({
      url: `${API_URL}/api/login`,
      method: 'POST',
      protocol: 'HTTP',
      body: requestBody,
      headers: { 'Content-Type': 'application/json' }
    });

    try {
      const response = await fetch(`${API_URL}/api/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: requestBody
      });

      const data = await response.json();

      if (data.success) {
        setUser(data.user);
        setToken(data.token);
        // VULNERABILITY: Storing token in localStorage
        localStorage.setItem('token', data.token);
        setMessage({ type: 'success', text: data.message });
      } else {
        setMessage({ type: 'error', text: data.message + (data.hint ? ` | Hint: ${data.hint}` : '') });
      }
    } catch (err) {
      setMessage({ type: 'error', text: `Koneksi gagal: ${err.message}` });
    }

    setLoading(false);
  };

  const handleTransfer = async (e) => {
    e.preventDefault();

    const requestBody = JSON.stringify({
      from: user.username,
      to: transferTo,
      amount: transferAmount,
      description: transferDesc
    });

    setLastRequest({
      url: `${API_URL}/api/transfer`,
      method: 'POST',
      protocol: 'HTTP',
      body: requestBody,
      headers: {
        'Content-Type': 'application/json',
        'Authorization': token
      }
    });

    try {
      const response = await fetch(`${API_URL}/api/transfer`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': token
        },
        body: requestBody
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
    setLastRequest(null);
    setTransferResult(null);
    localStorage.removeItem('token');
    setUsername('');
    setPassword('');
  };

  return (
    <div className="app-container">
      {/* Warning Banner */}
      <div className="warning-banner">
        <span className="icon">⚠️</span>
        <div className="text">
          <strong>DEMO VULNERABLE APP</strong> — Aplikasi ini berjalan tanpa enkripsi.
          Seluruh data dikirim dalam <span className="badge">PLAINTEXT</span>
        </div>
      </div>

      <div className="login-card">
        {/* Logo */}
        <div className="logo">
          <span className="icon">🏦</span>
          <h1>SecureBank</h1>
          <p className="subtitle">Internet Banking Portal</p>
        </div>

        {/* Protocol Badge */}
        <div className="protocol-badge">
          <span className="dot"></span>
          <span>HTTP — TIDAK TERENKRIPSI</span>
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
              />
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
              />
            </div>
            <button type="submit" className="btn-login" disabled={loading}>
              {loading ? 'Memproses...' : 'Login'}
            </button>
          </form>
        ) : (
          /* Dashboard (after login) */
          <>
            <div className="dashboard">
              <h3>👤 Profil Pengguna</h3>
              <div className="info-row">
                <span className="label">Username</span>
                <span className="value">{user.username}</span>
              </div>
              <div className="info-row">
                <span className="label">Email</span>
                <span className="value">{user.email}</span>
              </div>
              <div className="info-row">
                <span className="label">Role</span>
                <span className="value">{user.role}</span>
              </div>
              {user.password && (
                <div className="info-row">
                  <span className="label">Password (EXPOSED!)</span>
                  <span className="value danger">{user.password}</span>
                </div>
              )}
              <div className="info-row">
                <span className="label">Protocol</span>
                <span className="value danger">HTTP (Tidak Aman)</span>
              </div>
            </div>

            {/* Transfer Form */}
            <div className="transfer-section">
              <h3>💸 Transfer Dana</h3>
              <form onSubmit={handleTransfer}>
                <div className="form-group">
                  <label>Penerima</label>
                  <input
                    type="text"
                    placeholder="Username penerima"
                    value={transferTo}
                    onChange={(e) => setTransferTo(e.target.value)}
                    required
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
                  />
                </div>
                <div className="form-group">
                  <label>Keterangan</label>
                  <input
                    type="text"
                    placeholder="Transfer pembayaran"
                    value={transferDesc}
                    onChange={(e) => setTransferDesc(e.target.value)}
                  />
                </div>
                <button type="submit" className="btn-login">Kirim Transfer</button>
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

      {/* Intercepted Data Display */}
      {lastRequest && (
        <div className="intercepted-data">
          <h4>🔍 Data yang Dapat Diintersep oleh Attacker (Plaintext HTTP)</h4>
          <pre>{`${lastRequest.method} ${lastRequest.url}
Protocol: ${lastRequest.protocol} (TIDAK TERENKRIPSI)

Headers:
${JSON.stringify(lastRequest.headers, null, 2)}

Body (TERBACA JELAS):
${lastRequest.body}`}</pre>
        </div>
      )}

      <div className="footer-info">
        Network Programming & Administration — Tugas Kelompok 5<br />
        MITRE ATT&CK: T1557.002 | OWASP: A04:2025
      </div>
    </div>
  );
}

export default App;
