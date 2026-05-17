module.exports = {
  PORT: parseInt(process.env.PORT || '4873'),
  UPSTREAM_REGISTRY: process.env.UPSTREAM_REGISTRY || 'https://registry.npmjs.org',
  SCAN_API_URL: process.env.SCAN_API_URL || 'http://localhost:8000',
  SCAN_TIMEOUT: parseInt(process.env.SCAN_TIMEOUT || '30000'),
  REDIS_URL: process.env.REDIS_URL || '',
  FAIL_MODE: process.env.FAIL_MODE || 'open', // 'open' or 'closed'
  CACHE_TTL: parseInt(process.env.CACHE_TTL || '86400'),
  MAX_TARBALL_SIZE: parseInt(process.env.MAX_TARBALL_SIZE || '52428800'), // 50MB
  LOG_LEVEL: process.env.LOG_LEVEL || 'info',
};
