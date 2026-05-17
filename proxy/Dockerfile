FROM node:20-alpine

WORKDIR /app

# Copy package metadata
COPY package*.json ./

# Install dependencies
RUN npm install --production

# Copy source code
COPY src/ ./src/

# Environment variables
ENV PORT=4873
ENV SCAN_API_URL=http://scanner:8000
ENV UPSTREAM_REGISTRY=https://registry.npmjs.org
ENV SCAN_TIMEOUT=30000

# Expose proxy port
EXPOSE 4873

# Start proxy server
CMD ["node", "src/server.js"]
