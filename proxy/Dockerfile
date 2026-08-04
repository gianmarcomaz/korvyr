# Korvyr npm registry proxy.
FROM node:20-alpine

WORKDIR /app

# Install exactly what package-lock.json pins, production dependencies only.
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY src/ ./src/

ENV KORVYR_PROXY_PORT=4873 \
    KORVYR_SCAN_API_URL=http://korvyr-scanner:8000 \
    KORVYR_REGISTRY_URL=https://registry.npmjs.org \
    KORVYR_SCAN_TIMEOUT=30000 \
    KORVYR_FAIL_MODE=open

EXPOSE 4873

CMD ["node", "src/server.js"]
