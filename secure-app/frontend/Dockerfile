FROM node:20-slim

# Install openssl for certificate generation
RUN apt-get update && apt-get install -y openssl bash && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package.json ./
RUN npm install

COPY . .

# Generate self-signed certs if they don't exist
RUN mkdir -p certs && \
    if [ ! -f certs/server.crt ]; then \
      openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
      -keyout certs/server.key -out certs/server.crt \
      -subj "/C=ID/ST=DKI Jakarta/L=Jakarta/O=Security Lab/OU=Network Security/CN=secure-frontend.local" \
      -addext "subjectAltName=DNS:localhost,DNS:secure-frontend.local,DNS:sec-frontend,IP:127.0.0.1"; \
    fi

EXPOSE 3443

# Build and serve with HTTPS
RUN npm run build
RUN npm install -g serve

CMD ["serve", "-s", "build", "-l", "3443", "--ssl-cert", "/app/certs/server.crt", "--ssl-key", "/app/certs/server.key"]
