FROM node:20-slim

WORKDIR /app

COPY package.json ./
RUN npm install

COPY . .

EXPOSE 5000

# VULNERABILITY: Running over HTTP
CMD ["node", "server.js"]
