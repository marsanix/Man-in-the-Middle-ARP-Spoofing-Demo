FROM node:20-alpine

# Install openssl for certificate generation
RUN apk add --no-cache openssl bash

WORKDIR /app

COPY package.json ./
RUN npm install

COPY . .

# Generate self-signed certs if they don't exist
RUN chmod +x certs/generate-certs.sh && \
    if [ ! -f certs/server.crt ]; then bash certs/generate-certs.sh; fi

EXPOSE 3443

# Build and serve with HTTPS
RUN npm run build
RUN npm install -g serve

CMD ["serve", "-s", "build", "-l", "3443", "--ssl-cert", "/app/certs/server.crt", "--ssl-key", "/app/certs/server.key"]
