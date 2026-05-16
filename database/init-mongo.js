/**
 * MongoDB Initialization Script
 * ==============================
 * Script ini dijalankan otomatis saat container MongoDB pertama kali distart.
 * 
 * Membuat 2 database dalam 1 instance MongoDB:
 * 1. vulnerable_db — password disimpan PLAINTEXT (TIDAK AMAN!)
 * 2. secure_db     — password disimpan sebagai BCRYPT HASH (AMAN)
 * 
 * Ini mendemonstrasikan bahwa keamanan bukan hanya soal infrastruktur,
 * tetapi bagaimana APLIKASI memperlakukan data sensitif.
 */

// ============================================================================
// DATABASE 1: vulnerable_db (Plaintext Passwords — TIDAK AMAN!)
// ============================================================================

db = db.getSiblingDB('vulnerable_db');

// VULNERABILITY: Password disimpan dalam plaintext!
db.users.insertMany([
  {
    username: 'admin',
    password: 'admin123',           // PLAINTEXT — bisa dibaca langsung!
    role: 'administrator',
    email: 'admin@company.com',
    created_at: new Date()
  },
  {
    username: 'user1',
    password: 'password123',        // PLAINTEXT
    role: 'user',
    email: 'user1@company.com',
    created_at: new Date()
  },
  {
    username: 'manager',
    password: 'manager456',         // PLAINTEXT
    role: 'manager',
    email: 'manager@company.com',
    created_at: new Date()
  }
]);

// VULNERABILITY: Tidak ada index unik pada username
// VULNERABILITY: Tidak ada TTL pada sessions

db.transactions.createCollection('transactions');

print('[INIT] vulnerable_db created with PLAINTEXT passwords');

// ============================================================================
// DATABASE 2: secure_db (Bcrypt Hashed Passwords — AMAN)
// ============================================================================

db = db.getSiblingDB('secure_db');

// SECURE: Password akan di-hash oleh aplikasi saat startup (bcrypt)
// Disini kita hanya membuat collection dengan index yang benar
db.createCollection('users');
db.users.createIndex({ username: 1 }, { unique: true });

db.createCollection('transactions');
db.transactions.createIndex({ created_at: 1 }, { expireAfterSeconds: 86400 }); // TTL 24h

db.createCollection('audit_logs');
db.audit_logs.createIndex({ timestamp: 1 }, { expireAfterSeconds: 604800 }); // TTL 7 hari

print('[INIT] secure_db created with proper indexes and TTL');
print('[INIT] Bcrypt passwords will be seeded by the secure-backend application');
