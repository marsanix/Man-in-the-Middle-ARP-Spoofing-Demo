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

EXPOSE 5443

CMD ["node", "server.js"]
