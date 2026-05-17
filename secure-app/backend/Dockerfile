FROM node:20-slim

# Install openssl for certificate generation
RUN apt-get update && apt-get install -y openssl bash && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package.json ./
RUN npm install

COPY . .

# Generate self-signed certs if they don't exist
RUN chmod +x certs/generate-certs.sh && \
    if [ ! -f certs/server.crt ]; then bash certs/generate-certs.sh; fi

EXPOSE 5443

CMD ["node", "server.js"]
