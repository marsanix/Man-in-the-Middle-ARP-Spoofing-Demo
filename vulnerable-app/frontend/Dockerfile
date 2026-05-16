FROM node:20-alpine

WORKDIR /app

# Copy package files
COPY package.json ./
RUN npm install

# Copy source code
COPY . .

# Build React app
RUN npm run build

# Serve with a simple static server
RUN npm install -g serve

EXPOSE 3000

# VULNERABILITY: Serving over HTTP (no HTTPS)
CMD ["serve", "-s", "build", "-l", "3000"]
