const fs = require('fs');
const path = require('path');

const logFilePath = path.join(__dirname, '..', 'logs.jsonl');

function logInfo(message, data = {}) {
  const logObj = {
    timestamp: new Date().toISOString(),
    level: 'info',
    message,
    ...data
  };
  console.log(JSON.stringify(logObj));
  fs.appendFileSync(logFilePath, JSON.stringify(logObj) + '\n');
}

function logWarn(message, data = {}) {
  const logObj = {
    timestamp: new Date().toISOString(),
    level: 'warn',
    message,
    ...data
  };
  console.warn(JSON.stringify(logObj));
  fs.appendFileSync(logFilePath, JSON.stringify(logObj) + '\n');
}

function logError(message, data = {}) {
  const logObj = {
    timestamp: new Date().toISOString(),
    level: 'error',
    message,
    ...data
  };
  console.error(JSON.stringify(logObj));
  fs.appendFileSync(logFilePath, JSON.stringify(logObj) + '\n');
}

function logScanDecision(packageStr, verdict, gnn_score, rules, decision, scan_ms, cached) {
  const logFn = verdict === 'malicious' ? logWarn : logInfo;
  logFn(`scan_complete: ${packageStr}`, {
    event: 'scan_complete',
    package: packageStr,
    verdict,
    gnn_score,
    rules: rules || [],
    decision,
    scan_ms,
    cached
  });
}

function logBlock(packageStr, evidence) {
  logWarn(`BLOCK: ${packageStr}`, {
    event: 'block',
    package: packageStr,
    evidence
  });
}

module.exports = {
  logInfo,
  logWarn,
  logError,
  logScanDecision,
  logBlock
};
