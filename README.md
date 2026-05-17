# 🔐 Network Security Lab — MITM & ARP Spoofing Attack Demonstration

**Tugas Mata Kuliah: Network Programming & Administration**  
**Kelompok: 5**

---

## 📋 Deskripsi Project

Project ini merupakan laboratorium keamanan jaringan berbasis container (Docker) yang mendemonstrasikan serangan **Man-in-the-Middle (MITM)** melalui **ARP Spoofing** terhadap aplikasi web. Project membandingkan dua versi aplikasi:

| Aspek | Vulnerable App (HTTP) | Secure App (HTTPS) |
|-------|----------------------|---------------------|
| Protocol | HTTP (Plaintext) | HTTPS (TLS 1.2+) |
| Credentials | Tidak terenkripsi | Terenkripsi |
| Database | MongoDB (plaintext pwd) | MongoDB (bcrypt hash) |
| Password Storage | Plaintext di DB | bcrypt (salt: 12) di DB |
| Auth Token | Base64 sederhana | JWT (1h expiry) |
| Security Headers | Tidak ada | Helmet (CSP, HSTS) |
| Rate Limiting | Tidak ada | 5 percobaan/15 menit |
| Input Validation | Tidak ada | express-validator |
| Audit Log | Tidak ada | MongoDB audit_logs |

## 🏗️ Arsitektur

```
  Docker Bridge Network (lab-network: 172.20.0.0/24) — Layer 2
  ┌────────────────────────────────────────────────────────────────┐
  │                                                                │
  │  ┌─────────────────┐              ┌─────────────────────────┐  │
  │  │ 🗡️ Attacker     │ ARP Spoof   │ 🎯 Client Victim        │  │
  │  │ (Kali Linux)    │────────────▶│ (webtop XFCE)           │  │
  │  │ 172.20.0.100    │              │ 172.20.0.10             │  │
  │  └─────────────────┘              │ ┌─────────────────────┐ │  │
  │                                    │ │ 🔒 ts-client       │ │  │
  │                                    │ └─────────────────────┘ │  │
  │                                    └─────────┬───────────────┘  │
  │                                              │                  │
  │  ┌────────────────────┐     ┌────────────────┴──────────────┐   │
  │  │ 🗄️ Database        │     │ 🔴 Vuln App      🟢 Sec App     │   │
  │  │ (MongoDB)          │◀────│ HTTP             HTTPS (TLS)    │   │
  │  │ 172.20.0.50 :27017 │◀────│ .20 :3000        .30 :3443      │   │
  │  │ ┌───────────────┐  │     │ .21 :5000        .31 :5443      │   │
  │  │ │vulnerable_db  │  │     └──────────────────┬──────────────┘ │
  │  │ ├───────────────┤  │                        │ ┌─────────┐    │
  │  │ │secure_db      │◀─┼─(Tailscale tunnel)─────┼─│ts-backend│    │
  │  │ ├───────────────┤  │                        │ └─────────┘    │
  │  │ │🔒 ts-database │  │                        └────────────────┘ │
  │  │ └───────────────┘  │                                           │
  │  └────────────────────┘                                           │
  └───────────────────────────────────────────────────────────────────┘
```

**Arsitektur Microservices:** Frontend, Backend, dan Database dipisahkan ke container masing-masing. Satu instance MongoDB melayani kedua aplikasi — perbedaan keamanan ada di **layer aplikasi** (bagaimana data disimpan dan ditransmisikan).

## 📂 Struktur File

```
Tugas Kelompok 5/
├── PRD.md                          # Product Requirements
├── README.md                       # Dokumentasi (file ini)
├── docker-compose.yml              # Docker Compose configuration
├── .env.example                    # Template environment variables
│
├── vulnerable-app/                 # Aplikasi Rentan (HTTP)
│   ├── frontend/
│   │   ├── Dockerfile
│   │   ├── package.json
│   │   ├── public/index.html
│   │   └── src/
│   │       ├── index.js
│   │       ├── App.jsx
│   │       └── App.css
│   └── backend/
│       ├── Dockerfile
│       ├── package.json
│       └── server.js
│
├── secure-app/                     # Aplikasi Aman (HTTPS)
│   ├── frontend/
│   │   ├── Dockerfile
│   │   ├── package.json
│   │   ├── public/index.html
│   │   └── src/
│   │       ├── index.js
│   │       ├── App.jsx
│   │       └── App.css
│   └── backend/
│       ├── Dockerfile
│       ├── package.json
│       ├── server.js
│       └── certs/
│           └── generate-certs.sh
│
├── database/                       # MongoDB Database (Shared)
│   └── init-mongo.js              # Init script (seed vulnerable_db + secure_db)
│
├── attacker/                       # Kali Linux Attacker Container
│   ├── Dockerfile                 # Kali + scapy, bettercap, tshark
│   └── requirements.txt
│
├── attack-scripts/                 # Script Serangan (mounted ke attacker)
│   ├── arp_spoof.py               # ARP Spoofing (T1557.002)
│   ├── sniff_credentials.py       # Credential Sniffing (T1040)
│   ├── wireshark_filters.txt      # Referensi filter Wireshark
│   └── bettercap/
│       ├── mitm_attack.cap        # Caplet ARP Spoof + Sniff
│       └── sniff_only.cap         # Caplet Sniff saja
│
├── tailscale/                      # Tailscale VPN State
│   ├── client/state/
│   ├── backend/state/
│   └── database/state/
│
└── docs/
    ├── LAPORAN.md                  # Laporan Lengkap
    └── PRESENTASI.html             # Slide Presentasi
```

## 🚀 Cara Menjalankan

### Prasyarat

- [Docker](https://docs.docker.com/get-docker/) & [Docker Compose](https://docs.docker.com/compose/install/)
- [Tailscale Account](https://tailscale.com/) — 1 auth key (opsional, untuk SSH management)

### Langkah 1: Setup

```bash
cp .env.example .env    # Edit .env jika menggunakan Tailscale
cd secure-app/backend/certs && bash generate-certs.sh && cd ../../..
docker compose build && docker compose up -d
```

### Langkah 2: Akses Client Victim

Buka browser host → `http://localhost:3080` (desktop XFCE webtop)

### Langkah 3: Jalankan Serangan (dari Kali Container)

```bash
docker compose exec attacker bash
```

#### Metode A: Scapy

```bash
python3 arp_spoof.py -t 172.20.0.10 -g 172.20.0.20          # Terminal 1
python3 sniff_credentials.py --mode http --port 5000          # Terminal 2
```

#### Metode B: Bettercap

```bash
bettercap -iface eth0 -caplet bettercap/mitm_attack.cap
```

#### Metode C: tshark

```bash
python3 arp_spoof.py -t 172.20.0.10 -g 172.20.0.20          # Terminal 1
tshark -i eth0 -f "arp or port 5000 or port 5443" -w /tmp/capture.pcap  # Terminal 2
```

### Langkah 4: Demo Login

1. Di webtop, buka `http://172.20.0.20:3000` → login `admin` / `admin123`
2. Terminal attacker → **kredensial tertangkap plaintext!**
3. Di webtop, buka `https://172.20.0.30:3443` → login sama
4. Terminal attacker → **data terenkripsi TLS, tidak terbaca!**

## 🔬 Referensi MITRE ATT&CK

| Technique ID | Nama | Deskripsi |
|-------------|------|-----------|
| T1557 | Adversary-in-the-Middle | Posisi attacker di antara victim dan server |
| T1557.002 | ARP Cache Poisoning | Meracuni ARP cache untuk redirect traffic |
| T1040 | Network Sniffing | Menangkap traffic yang melewati attacker |

## 🛡️ Referensi OWASP Top 10:2025

| ID | Nama | Relevansi |
|----|------|-----------|
| A04:2025 | Cryptographic Failures | HTTP tanpa enkripsi = plaintext credentials |
| A02:2025 | Security Misconfiguration | Tidak ada security headers, CORS terbuka |
| A07:2025 | Authentication Failures | Password plaintext, token tanpa expiry |

## 🔧 Credential Test

| Username | Password | Role |
|----------|----------|------|
| admin | admin123 | administrator |
| user1 | password123 | user |
| manager | manager456 | manager |

## ⚠️ Disclaimer

**Project ini dibuat HANYA untuk tujuan EDUKASI** dalam lingkungan lab yang terisolasi. Penggunaan teknik yang didemonstrasikan terhadap sistem tanpa izin adalah **ILEGAL** dan melanggar hukum.

---

**Network Programming & Administration — Semester 5**
