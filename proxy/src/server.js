const express = require('express');
const cors = require('cors');
const fs = require('fs');
const { request } = require('undici');
const config = require('./config');
const logger = require('./logger');
const cache = require('./cache');
const scanner = require('./scanner');

const app = express();
app.use(cors());

app.get('/api/logs', (req, res) => {
  const logFilePath = config.LOG_FILE;
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

    const declaredSize = parseInt(upstreamRes.headers['content-length'] || '0', 10);
    if (declaredSize > config.MAX_TARBALL_SIZE) {
      logger.logWarn(`Tarball too large to scan: ${name}@${version}`, {
        event: 'scan_skipped',
        package: `${name}@${version}`,
        size: declaredSize,
        limit: config.MAX_TARBALL_SIZE,
      });
      return handleUnscannable(res, name, version, 'tarball exceeds KORVYR_MAX_TARBALL_SIZE', () =>
        upstreamRes.body.pipe(res)
      );
    }

    const tarballBuffer = Buffer.from(await upstreamRes.body.arrayBuffer());
    const scanResult = await scanner.scanTarball(tarballBuffer, name, version);
    await cache.setCachedResult(name, version, scanResult);

    logger.logScanDecision(
      `${name}@${version}`,
      scanResult.verdict,
      scanResult.gnn_score,
      scanResult.rules_matched?.map((r) => r.rule_id),
      scanResult.decision_path || scanResult.error,
      scanResult.scan_time_ms || 0,
      false
    );

    if (scanResult.verdict === 'malicious') {
      logger.logBlock(`${name}@${version}`, scanResult.evidence);
      return sendBlockResponse(res, name, version, scanResult);
    }

    if (scanResult.verdict === 'error') {
      // The scanner could not produce a verdict. Default deployment is
      // fail-open: the package is forwarded UNSCANNED and the event is logged.
      return handleUnscannable(res, name, version, scanResult.error, () =>
        sendTarball(res, tarballBuffer)
      );
    }

    // clean and suspicious are both forwarded; suspicious is recorded above so
    // the verdict is reviewable in the proxy log and dashboard.
    return sendTarball(res, tarballBuffer);
  } catch (err) {
    logger.logError(`Failed to process tarball ${name}@${version}`, { error: err.message });
    res.status(502).send('Bad Gateway');
  }
});

function sendTarball(res, buffer) {
  res.status(200);
  res.setHeader('Content-Type', 'application/octet-stream');
  res.setHeader('Content-Length', buffer.length);
  return res.end(buffer);
}

/**
 * Decide what to do with a package that could not be scanned.
 * Fail-open (default) forwards it with a loud warning; fail-closed refuses it.
 */
function handleUnscannable(res, name, version, reason, forward) {
  if (config.FAIL_MODE === 'closed') {
    logger.logWarn(`FAIL-CLOSED: refused unscanned ${name}@${version}`, {
      event: 'fail_closed',
      package: `${name}@${version}`,
      reason,
    });
    return res.status(503).json({
      error: 'Korvyr could not scan this package',
      package: `${name}@${version}`,
      verdict: 'unscanned',
      reason,
      info: 'The proxy is configured with KORVYR_FAIL_MODE=closed, so unscanned packages are refused.',
    });
  }

  logger.logWarn(
    `Korvyr scanner unavailable - ${name}@${version} forwarded WITHOUT scanning. Reason: ${reason}`,
    { event: 'fail_open', package: `${name}@${version}`, reason }
  );
  return forward();
}

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
  const confidence = typeof result.confidence === 'number' ? result.confidence.toFixed(2) : 'n/a';
  const agentDirective = `Korvyr blocked the installation of ${name}@${version}.
VERDICT: malicious (model+rules confidence ${confidence}).
EVIDENCE: ${result.evidence && result.evidence.length ? result.evidence.join('; ') : 'none recorded'}.
DECISION PATH: ${result.decision_path}.
NEXT STEP: review the evidence above before installing. Korvyr is a research prototype and can be wrong in both directions.`;

  res.status(403).json({
    error: 'Blocked by Korvyr',
    package: `${name}@${version}`,
    verdict: 'malicious',
    confidence: result.confidence,
    evidence: result.evidence || [],
    decision: result.decision_path,
    agent_directive: agentDirective,
    info: 'Korvyr flagged this package as malicious. This is a research-prototype verdict, not an authoritative one.',
  });
}

if (require.main === module) {
  app.listen(config.PORT, () => {
    logger.logInfo(`Korvyr Proxy listening on http://localhost:${config.PORT}`, {
      upstream: config.UPSTREAM_REGISTRY,
      scanner: config.SCAN_API_URL
    });
  });
}

module.exports = { app, parseTarballUrl };
