const fs = require('fs');
const config = require('./config');

// The three log helpers only differed by level and console channel, so one
// emit() carries the shared JSONL formatting, level filtering, and file sink.
const LEVELS = { debug: 10, info: 20, warn: 30, error: 40 };
const CONSOLE = { debug: console.debug, info: console.log, warn: console.warn, error: console.error };

const threshold = LEVELS[config.LOG_LEVEL] || LEVELS.info;
let fileSinkWarned = false;

function emit(level, message, data = {}) {
  if (LEVELS[level] < threshold) return;

  const line = JSON.stringify({
    timestamp: new Date().toISOString(),
    level,
    message,
    ...data,
  });

  (CONSOLE[level] || console.log)(line);

  try {
    fs.appendFileSync(config.LOG_FILE, line + '\n');
  } catch (err) {
    // A read-only or missing log directory must not take the proxy down.
    if (!fileSinkWarned) {
      fileSinkWarned = true;
      console.warn(`korvyr-proxy: cannot write ${config.LOG_FILE}: ${err.message}`);
    }
  }
}

const logInfo = (message, data) => emit('info', message, data);
const logWarn = (message, data) => emit('warn', message, data);
const logError = (message, data) => emit('error', message, data);

function logScanDecision(packageStr, verdict, gnn_score, rules, decision, scan_ms, cached) {
  emit(verdict === 'malicious' ? 'warn' : 'info', `scan_complete: ${packageStr}`, {
    event: 'scan_complete',
    package: packageStr,
    verdict,
    gnn_score,
    rules: rules || [],
    decision,
    scan_ms,
    cached,
  });
}

function logBlock(packageStr, evidence) {
  logWarn(`BLOCK: ${packageStr}`, {
    event: 'block',
    package: packageStr,
    evidence,
  });
}

module.exports = {
  logInfo,
  logWarn,
  logError,
  logScanDecision,
  logBlock,
};
