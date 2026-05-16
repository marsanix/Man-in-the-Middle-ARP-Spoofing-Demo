#!/bin/bash
# Generate self-signed TLS certificates for the secure demo server
# These are for DEVELOPMENT/DEMO purposes only

CERT_DIR="$(dirname "$0")"

echo "🔐 Generating self-signed TLS certificates..."

openssl req -x509 -nodes -days 365 \
  -newkey rsa:2048 \
  -keyout "$CERT_DIR/server.key" \
  -out "$CERT_DIR/server.crt" \
  -subj "/C=ID/ST=DKI Jakarta/L=Jakarta/O=Security Lab/OU=Network Security/CN=secure-app.local" \
  -addext "subjectAltName=DNS:localhost,DNS:secure-app.local,DNS:secure-backend,IP:127.0.0.1"

echo "✅ Certificates generated successfully!"
echo "   Key:  $CERT_DIR/server.key"
echo "   Cert: $CERT_DIR/server.crt"
