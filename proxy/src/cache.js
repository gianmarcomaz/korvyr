const Redis = require('ioredis');
const NodeCache = require('node-cache');
const config = require('./config');
const logger = require('./logger');

const memoryCache = new NodeCache({ stdTTL: config.CACHE_TTL, checkperiod: 600 });
let redis = null;

if (config.REDIS_URL) {
  redis = new Redis(config.REDIS_URL, {
    maxRetriesPerRequest: 3,
    retryStrategy(times) {
      if (times > 3) return null; // Fallback to memory
      return Math.min(times * 50, 2000);
    }
  });

  redis.on('error', (err) => {
    logger.logWarn('Redis connection error, falling back to memory cache', { error: err.message });
  });
}

async function getCachedResult(name, version) {
  const key = `${name}@${version}`;
  
  if (redis && redis.status === 'ready') {
    try {
      const data = await redis.get(key);
      if (data) return JSON.parse(data);
    } catch (err) {
      logger.logError('Redis GET error', { error: err.message });
    }
  }
  
  return memoryCache.get(key);
}

async function setCachedResult(name, version, result) {
  const key = `${name}@${version}`;
  
  if (redis && redis.status === 'ready') {
    try {
      await redis.set(key, JSON.stringify(result), 'EX', config.CACHE_TTL);
    } catch (err) {
      logger.logError('Redis SET error', { error: err.message });
    }
  }
  
  memoryCache.set(key, result);
}

function getCacheStats() {
  return {
    redis_active: redis && redis.status === 'ready',
    memory_stats: memoryCache.getStats()
  };
}

module.exports = {
  getCachedResult,
  setCachedResult,
  getCacheStats
};
