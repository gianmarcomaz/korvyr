const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const { request } = require('undici');
const config = require('./config');
const logger = require('./logger');
const cache = require('./cache');
const scanner = require('./scanner');

const app = express();
app.use(cors());

app.get('/api/logs', (req, res) => {
  const logFilePath = path.join(__dirname, '..', 'logs.jsonl');
  if (!fs.existsSync(logFilePath)) return res.json([]);
  
  const content = fs.readFileSync(logFilePath, 'utf-8');
  const logs = content.trim().split('\n').map(line => {
    try { return JSON.parse(line); } catch (e) { return null; }
  }).filter(Boolean).reverse(); // Newest first
  
  res.json(logs);
});

function parseTarballUrl(path) {
  // Decode the full path first to handle @scope%2fpackage
  const decodedPath = decodeURIComponent(path);
  
  // Look for /-/ indicating a tarball
  const tarballIndex = decodedPath.indexOf('/-/');
  if (tarballIndex === -1 || !decodedPath.endsWith('.tgz')) {
    return { isTarball: false };
  }

  // The name is everything before /-/
  const name = decodedPath.substring(1, tarballIndex);
  
  // The filename is everything after /-/
  const filename = decodedPath.substring(tarballIndex + 3);
  
  // The filename is usually name-version.tgz, but name can have a scope.
  // filename = nameWithoutScope-version.tgz
  let nameWithoutScope = name;
  if (name.startsWith('@')) {
    nameWithoutScope = name.split('/')[1];
  }
  
  // Extract version by removing nameWithoutScope- and .tgz
  const prefix = `${nameWithoutScope}-`;
  if (!filename.startsWith(prefix)) {
    return { isTarball: false }; // Unexpected format
  }
  
  const version = filename.substring(prefix.length, filename.length - 4);
  return { isTarball: true, name, version };
}

app.use(async (req, res) => {
  const urlInfo = parseTarballUrl(req.path);
  const upstreamUrl = `${config.UPSTREAM_REGISTRY}${req.url}`;
  
  const headers = { ...req.headers };
  delete headers.host; // Let undici set the host

  if (!urlInfo.isTarball) {
    // Category 1: Metadata - pass through
    try {
      const upstreamRes = await request(upstreamUrl, {
        method: req.method,
        headers,
        body: req.method !== 'GET' && req.method !== 'HEAD' ? req : undefined
      });
      res.status(upstreamRes.statusCode);
      for (const [key, value] of Object.entries(upstreamRes.headers)) {
        res.setHeader(key, value);
      }
      upstreamRes.body.pipe(res);
    } catch (err) {
      logger.logError(`Proxy error for ${req.path}`, { error: err.message });
      res.status(502).send('Bad Gateway');
    }
    return;
  }

  // Category 2: Tarball
  const { name, version } = urlInfo;
  
  // Check cache
  const cachedResult = await cache.getCachedResult(name, version);
  if (cachedResult) {
    if (cachedResult.verdict === 'malicious') {
      logger.logBlock(`${name}@${version}`, cachedResult.evidence);
      return sendBlockResponse(res, name, version, cachedResult);
    }
    logger.logScanDecision(`${name}@${version}`, cachedResult.verdict, cachedResult.gnn_score, cachedResult.rules_matched?.map(r=>r.rule_id), cachedResult.decision_path, 0, true);
    return pipeTarball(upstreamUrl, headers, res);
  }

  // Download tarball into memory
  try {
    const upstreamRes = await request(upstreamUrl, { method: 'GET', headers });
    if (upstreamRes.statusCode !== 200) {
      res.status(upstreamRes.statusCode);
      for (const [key, value] of Object.entries(upstreamRes.headers)) {
        res.setHeader(key, value);
      }
      return upstreamRes.body.pipe(res);
    }

    const tarballBuffer = Buffer.from(await upstreamRes.body.arrayBuffer());

    // Scan
    const scanResult = await scanner.scanTarball(tarballBuffer, name, version);
    
    // Cache
    await cache.setCachedResult(name, version, scanResult);
    
    logger.logScanDecision(
      `${name}@${version}`, 
      scanResult.verdict, 
      scanResult.gnn_score, 
      scanResult.rules_matched?.map(r => r.rule_id), 
      scanResult.decision_path || scanResult.error, 
      scanResult.scan_time_ms || 0, 
      false
    );

    if (scanResult.verdict === 'malicious') {
      logger.logBlock(`${name}@${version}`, scanResult.evidence);
      return sendBlockResponse(res, name, version, scanResult);
    } else if (scanResult.verdict === 'suspicious') {
      // Pipe it anyway
      res.status(200);
      res.setHeader('Content-Type', 'application/octet-stream');
      res.setHeader('Content-Length', tarballBuffer.length);
      return res.end(tarballBuffer);
    } else if (scanResult.verdict === 'error') {
      logger.logWarn(`[WARN] SupplyGuard scanner unreachable or failed — package ${name}@${version} forwarded without scanning. SCANNING IS CURRENTLY DEGRADED. Error: ${scanResult.error}`);
      res.status(200);
      res.setHeader('Content-Type', 'application/octet-stream');
      res.setHeader('Content-Length', tarballBuffer.length);
      return res.end(tarballBuffer);
    } else {
      // Clean
      res.status(200);
      res.setHeader('Content-Type', 'application/octet-stream');
      res.setHeader('Content-Length', tarballBuffer.length);
      return res.end(tarballBuffer);
    }
  } catch (err) {
    logger.logError(`Failed to process tarball ${name}@${version}`, { error: err.message });
    res.status(502).send('Bad Gateway');
  }
});

async function pipeTarball(upstreamUrl, headers, res) {
  try {
    const upstreamRes = await request(upstreamUrl, { method: 'GET', headers });
    res.status(upstreamRes.statusCode);
    for (const [key, value] of Object.entries(upstreamRes.headers)) {
      res.setHeader(key, value);
    }
    upstreamRes.body.pipe(res);
  } catch (err) {
    res.status(502).send('Bad Gateway');
  }
}

function sendBlockResponse(res, name, version, result) {
  const llmFriendlyMessage = `[AGENT-ALERT] Installation of ${name}@${version} was BLOCKED by the SupplyGuard Agentic Firewall.
REASON: Structural malicious intent detected (Confidence: ${result.confidence.toFixed(2)}).
EVIDENCE: ${result.evidence ? result.evidence.join('; ') : 'Topology anomaly'}.
DECISION PATH: ${result.decision_path}.
ACTION REQUIRED: Do not attempt to install this package. Choose an alternative package or notify the human operator.`;

  res.status(403).json({
    error: "BLOCKED by SupplyGuard Agentic Firewall",
    package: `${name}@${version}`,
    verdict: "malicious",
    confidence: result.confidence,
    evidence: result.evidence || [],
    decision: result.decision_path,
    agent_directive: llmFriendlyMessage,
    info: "This package was identified as malicious by structural analysis and blocked to protect the sandbox environment."
  });
}

if (require.main === module) {
  app.listen(config.PORT, () => {
    logger.logInfo(`SupplyGuard Proxy listening on http://localhost:${config.PORT}`, {
      upstream: config.UPSTREAM_REGISTRY,
      scanner: config.SCAN_API_URL
    });
  });
}

module.exports = { app, parseTarballUrl };
