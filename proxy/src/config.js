const path = require('path');

// All proxy configuration is KORVYR_-prefixed so the scanner API, the proxy,
// and docker-compose read from one documented namespace (see .env.example).
module.exports = {
  PORT: parseInt(process.env.KORVYR_PROXY_PORT || '4873', 10),
  UPSTREAM_REGISTRY: process.env.KORVYR_REGISTRY_URL || 'https://registry.npmjs.org',
  SCAN_API_URL: process.env.KORVYR_SCAN_API_URL || 'http://localhost:8000',
  SCAN_TIMEOUT: parseInt(process.env.KORVYR_SCAN_TIMEOUT || '30000', 10),
  REDIS_URL: process.env.KORVYR_REDIS_URL || '',
  // 'open'   -> forward the package when the scanner cannot be reached (default)
  // 'closed' -> refuse the package when the scanner cannot be reached
  FAIL_MODE: process.env.KORVYR_FAIL_MODE === 'closed' ? 'closed' : 'open',
  CACHE_TTL: parseInt(process.env.KORVYR_CACHE_TTL || '86400', 10),
  MAX_TARBALL_SIZE: parseInt(process.env.KORVYR_MAX_TARBALL_SIZE || '52428800', 10), // 50MB
  LOG_LEVEL: process.env.KORVYR_LOG_LEVEL || 'info',
  LOG_FILE: process.env.KORVYR_LOG_FILE || path.join(__dirname, '..', 'logs.jsonl'),
};
