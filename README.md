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
| Password Storage | Plaintext | bcrypt (salt: 12) |
| Auth Token | Base64 sederhana | JWT (1h expiry) |
| Security Headers | Tidak ada | Helmet (CSP, HSTS) |
| Rate Limiting | Tidak ada | 5 percobaan/15 menit |
| Input Validation | Tidak ada | express-validator |

## 🏗️ Arsitektur

```
┌─────────────────────────────────────────────────────────────────┐
│                     HOST (Attacker)                              │
│   ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│   │ ARP Spoofer  │  │ Credential   │  │ Bettercap / Wireshark│  │
│   │ (Scapy)      │  │ Sniffer      │  │ (MITM tools)         │  │
│   └──────┬───────┘  └──────┬───────┘  └──────────┬───────────┘  │
│          └────────┬────────┘                      │              │
│                   │      Tailscale Network        │              │
│   ┌───────────────┼──────────────────────────────┼──────────┐   │
│   │               │  Docker Compose Environment  │          │   │
│   │               │                              │          │   │
│   │  ┌────────────┴────────────┐                 │          │   │
│   │  │ Client Victim (webtop)  │◀── ARP Poison ──┘          │   │
│   │  │ ┌────────────────────┐  │                            │   │
│   │  │ │ Tailscale Sidecar  │  │   ← TS_AUTHKEY_CLIENT      │   │
│   │  │ └────────────────────┘  │                            │   │
│   │  │ ┌────────────────────┐  │                            │   │
│   │  │ │ XFCE Desktop + 🌐  │  │   ← http://localhost:3080  │   │
│   │  │ │ (Alpine webtop)    │  │                            │   │
│   │  │ └────────────────────┘  │                            │   │
│   │  └──────────┬──────────────┘                            │   │
│   │             │ browses to                                │   │
│   │  ┌──────────┴────────┐  ┌───────────────┐              │   │
│   │  │ Vulnerable Stack  │  │ Secure Stack  │              │   │
│   │  │ (Tailscale)       │  │ (Tailscale)   │              │   │
│   │  │ ┌──────┐┌───────┐ │  │ ┌──────┐┌───┐│              │   │
│   │  │ │React ││Express│ │  │ │React ││Exp.││              │   │
│   │  │ │:3000 ││:5000  │ │  │ │:3443 ││5443││              │   │
│   │  │ │ HTTP ││ HTTP  │ │  │ │HTTPS ││TLS ││              │   │
│   │  │ └──────┘└───────┘ │  │ └──────┘└───┘│              │   │
│   │  └───────────────────┘  └──────────────┘              │   │
│   └───────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

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
├── attack-scripts/                 # Script Serangan
│   ├── requirements.txt
│   ├── arp_spoof.py               # ARP Spoofing (T1557.002)
│   ├── sniff_credentials.py       # Credential Sniffing (T1040)
│   ├── wireshark_filters.txt      # Referensi filter Wireshark
│   └── bettercap/
│       ├── mitm_attack.cap        # Caplet ARP Spoof + Sniff
│       └── sniff_only.cap         # Caplet Sniff saja
│
├── tailscale/                      # Tailscale Configuration
│   ├── vulnerable/
│   │   ├── config/serve.json
│   │   └── state/
│   └── secure/
│       ├── config/serve.json
│       └── state/
│
└── docs/
    └── LAPORAN.md                  # Laporan Lengkap
```

## 🚀 Cara Menjalankan

### Prasyarat

- [Docker](https://docs.docker.com/get-docker/) & [Docker Compose](https://docs.docker.com/compose/install/)
- [Tailscale Account](https://tailscale.com/) dengan auth keys
- Python 3.8+ (untuk attack scripts di host)
- `pip install scapy colorama` (untuk attack scripts)
- [Wireshark](https://www.wireshark.org/download.html) (GUI packet analyzer + tshark CLI)
- [Bettercap](https://www.bettercap.org/installation/) (MITM framework)

### Langkah 1: Konfigurasi Environment

```bash
# Clone/navigate ke project
cd "Tugas Kelompok 5"

# Copy environment template
cp .env.example .env

# Edit .env dan masukkan Tailscale auth keys
# Generate keys di: https://login.tailscale.com/admin/settings/keys
```

### Langkah 2: Generate TLS Certificates (Secure App)

```bash
cd secure-app/backend/certs
bash generate-certs.sh
cd ../../..
```

### Langkah 3: Build & Start Containers

```bash
# Build semua images
docker compose build

# Start semua containers
docker compose up -d

# Cek status
docker compose ps
```

### Langkah 4: Verifikasi Tailscale

```bash
# Cek status Tailscale
tailscale status

# Catat IP Tailscale dari container:
# vulnerable-app → 100.x.x.x
# secure-app     → 100.x.x.y
```

### Langkah 5: Akses Aplikasi

| Aplikasi | URL | Deskripsi |
|----------|-----|-----------|
| Vulnerable Frontend | `http://vulnerable-app:3000` | Login tanpa enkripsi |
| Vulnerable Backend | `http://vulnerable-app:5000` | API tanpa enkripsi |
| Secure Frontend | `https://secure-app:3443` | Login dengan TLS |
| Secure Backend | `https://secure-app:5443` | API dengan TLS |

### Langkah 6: Jalankan Serangan (dari Host)

Tersedia **3 metode** serangan. Lihat `docs/LAPORAN.md` Section 3.5 untuk panduan lengkap.

#### Metode A: Scapy + Python Sniffer

```bash
cd attack-scripts
pip install -r requirements.txt

# Terminal 1: ARP Spoofing (target = client-victim, gateway = server)
sudo python3 arp_spoof.py -t <CLIENT_VICTIM_IP> -g <VULNERABLE_APP_IP>

# Terminal 2: Sniff HTTP credentials
sudo python3 sniff_credentials.py --mode http --port 5000
```

#### Metode B: Bettercap (All-in-One MITM)

```bash
# Jalankan Bettercap pada interface Tailscale
sudo bettercap -iface tailscale0 -caplet bettercap/mitm_attack.cap
```

#### Metode C: Scapy + Wireshark

```bash
# Terminal 1: ARP Spoofing
sudo python3 arp_spoof.py -t <CLIENT_VICTIM_IP> -g <VULNERABLE_APP_IP>

# Terminal 2: Buka Wireshark GUI
wireshark &
# → Pilih interface tailscale0
# → Set capture filter: arp or port 5000 or port 5443
```

### Langkah 7: Analisis dengan Wireshark

1. Buka file capture (dari Bettercap atau tshark) di Wireshark
2. Gunakan filter dari `wireshark_filters.txt`:
   - **Deteksi ARP Spoofing**: `arp.opcode == 2`
   - **Lihat kredensial HTTP**: `http.request.method == "POST"` → klik kanan → **Follow → HTTP Stream**
   - **Verifikasi HTTPS aman**: `tcp.port == 5443 && tls` → data terenkripsi
3. Bandingkan: HTTP traffic **plaintext** vs HTTPS traffic **encrypted**

### Langkah 8: Demo Login

1. Buka browser → akses `http://vulnerable-app:3000`
2. Login dengan: `admin` / `admin123`
3. Lihat terminal sniffer/Bettercap → **kredensial tertangkap dalam plaintext!**
4. Buka Wireshark → Follow HTTP Stream → **username & password terbaca!**
5. Buka browser → akses `https://secure-app:3443`
6. Login dengan credentials yang sama
7. Lihat Wireshark → **data terenkripsi TLS, tidak terbaca!**

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
