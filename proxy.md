# Prompt: Build the npm Registry Proxy for Real-Time Package Interception

We have a working FastAPI scanning server (supplyguard.api.server) that accepts package tarballs and returns scan verdicts. We have a working CLI. Now we need the final piece: a proxy server that sits between the developer's `npm install` command and the npm registry, intercepting every package download and scanning it before it reaches the developer's machine.

This is the core product feature — real-time interception, not after-the-fact detection.

---

## Architecture Overview

The proxy is a **separate Node.js server** (Express or Fastify) that acts as an npm registry mirror. It does NOT replace the FastAPI server — it sits in front of it and calls it for scanning decisions.

```
Developer runs: npm install axios

npm client ──► SupplyGuard Proxy (Node.js, port 4873)
                    │
                    ├── Metadata requests → forwarded to registry.npmjs.org transparently
                    │
                    ├── Tarball requests → proxy downloads tarball first
                    │       │
                    │       ├── Check cache: scanned before? → return cached verdict
                    │       │
                    │       ├── Cache miss → send tarball to FastAPI server for scanning
                    │       │       │
                    │       │       ├── Verdict: clean → forward tarball to npm client
                    │       │       ├── Verdict: suspicious → forward + log warning
                    │       │       └── Verdict: malicious → BLOCK, return error to npm client
                    │       │
                    │       └── FastAPI unreachable → fail-open (forward + log warning)
                    │
                    └── All other requests → forwarded transparently
```

The developer configures their `.npmrc` to point at the proxy:
```
registry=http://localhost:4873/
```

After that, every `npm install` goes through the proxy. The developer doesn't change anything else about their workflow.

---

## What to Build

### File Structure

```
proxy/
├── package.json
├── src/
│   ├── server.js          # Main Express/Fastify server
│   ├── scanner.js         # Client that calls the FastAPI scanning API
│   ├── cache.js           # In-memory scan result cache
│   ├── logger.js          # Structured logging
│   └── config.js          # Configuration (ports, upstream registry, API URL, etc.)
├── test/
│   └── proxy.test.js      # Integration tests
└── README.md
```

Use Express (not Fastify) for simplicity. Dependencies: `express`, `http-proxy-middleware` or manual proxying with `node-fetch`/`undici`, and `node-cache` for TTL-based caching.

### server.js — The Main Proxy Server

The proxy needs to handle two categories of npm registry traffic:

**Category 1: Metadata requests (pass through transparently)**

These are requests npm makes to get package information — available versions, dependency trees, dist-tags. They look like:

- `GET /{package_name}` — package metadata JSON
- `GET /{package_name}/{version}` — specific version metadata
- `GET /-/v1/search?text=...` — search
- `GET /-/npm/v1/security/advisories` — audit endpoint
- `GET /@{scope}%2f{package}` — scoped package metadata

These should be proxied transparently to `https://registry.npmjs.org` with zero modification. Don't scan metadata, don't delay it, don't touch it. Just forward the request and pipe the response back.

**Category 2: Tarball downloads (intercept and scan)**

These are the actual package files. They look like:

- `GET /{package_name}/-/{package_name}-{version}.tgz`
- `GET /@{scope}/{package}/-/{package}-{version}.tgz`

This is where interception happens. When the proxy sees a tarball request:

```
1. Extract package name and version from the URL
2. Check the cache: have we scanned this exact name@version before?
   → YES: if verdict was clean/suspicious, proxy the tarball from upstream normally
          if verdict was malicious, return 403 with block message
   → NO: continue to step 3

3. Download the tarball from the upstream registry into a buffer (don't stream directly to the client)
4. Send the tarball buffer to the FastAPI scanning server: POST http://localhost:8000/scan/tarball
5. Wait for the scanning result (timeout: 30 seconds)
6. Cache the result (keyed by name@version, TTL: 24 hours)
7. Based on verdict:
   → clean: pipe the already-downloaded tarball buffer to the npm client
   → suspicious: pipe the tarball + log a warning to console
   → malicious: return 403 to the npm client with a clear error message
   → scan error/timeout: fail-open — pipe the tarball + log the error (don't block installs because the scanner is down)
```

### The Critical Design Decisions

**1. Download-then-scan, not stream-then-scan.**

The proxy must download the full tarball into memory before sending it to the scanner. You can't stream the tarball to both the scanner and the npm client simultaneously because you need the scan result before deciding whether to forward it. If you start streaming to the client and then discover it's malicious, it's too late — npm has already started extracting files.

This means tarball requests take slightly longer (download to proxy → scan → forward to client, instead of just streaming through). For a typical package (100KB-5MB), the download adds <1 second. The scan adds 2-5 seconds. Total overhead: 3-6 seconds per uncached package. Cached packages add <10ms.

**2. Fail-open, not fail-closed.**

If the FastAPI scanning server is unreachable, the proxy should forward the package anyway and log a warning — NOT block the install. If the proxy blocks installs when the scanner is down, a scanner outage becomes a company-wide outage where nobody can install packages. That's unacceptable. Enterprise teams will rip out any tool that can take down their development workflow.

Log a prominent warning: `[WARN] SupplyGuard scanner unreachable — package {name}@{version} forwarded without scanning. SCANNING IS CURRENTLY DEGRADED.`

**3. Transparent auth token forwarding.**

npm sends auth tokens in the `Authorization` header for private registry access. The proxy must forward these headers to the upstream registry without modification and without logging them. Never log, store, or inspect auth tokens.

### scanner.js — FastAPI Client

A simple module that sends tarballs to the scanning server and returns the result.

```javascript
// scanner.js

const SCAN_API_URL = process.env.SCAN_API_URL || 'http://localhost:8000';
const SCAN_TIMEOUT = parseInt(process.env.SCAN_TIMEOUT || '30000'); // 30 seconds

async function scanTarball(tarballBuffer, packageName, version) {
  try {
    // Create a FormData with the tarball buffer
    // POST to ${SCAN_API_URL}/scan/tarball
    // Return the parsed JSON response

    // On success: return { verdict, confidence, gnn_score, rules_matched, evidence, decision_path }
    // On timeout: return { verdict: 'error', error: 'Scan timeout' }
    // On connection error: return { verdict: 'error', error: 'Scanner unreachable' }
  } catch (err) {
    return { verdict: 'error', error: err.message };
  }
}
```

Important: Use `undici` or `node-fetch` for HTTP requests. Set a 30-second timeout. If the scanner takes longer than 30 seconds, fail-open.

### cache.js — Scan Result Cache

Simple in-memory cache using `node-cache` with TTL.

```javascript
// cache.js
const NodeCache = require('node-cache');

// TTL: 24 hours. Check period: 10 minutes.
const cache = new NodeCache({ stdTTL: 86400, checkperiod: 600 });

function getCachedResult(name, version) {
  return cache.get(`${name}@${version}`);
}

function setCachedResult(name, version, result) {
  cache.set(`${name}@${version}`, result);
}

function getCacheStats() {
  return cache.getStats();
}
```

For the MVP, in-memory cache is fine. It resets when the proxy restarts. Redis comes later when you need persistence across restarts and shared cache across multiple proxy instances.

### config.js — Configuration

```javascript
module.exports = {
  PORT: parseInt(process.env.PORT || '4873'),
  UPSTREAM_REGISTRY: process.env.UPSTREAM_REGISTRY || 'https://registry.npmjs.org',
  SCAN_API_URL: process.env.SCAN_API_URL || 'http://localhost:8000',
  SCAN_TIMEOUT: parseInt(process.env.SCAN_TIMEOUT || '30000'),
  FAIL_MODE: process.env.FAIL_MODE || 'open', // 'open' or 'closed'
  CACHE_TTL: parseInt(process.env.CACHE_TTL || '86400'),
  MAX_TARBALL_SIZE: parseInt(process.env.MAX_TARBALL_SIZE || '52428800'), // 50MB
  LOG_LEVEL: process.env.LOG_LEVEL || 'info',
};
```

### logger.js — Structured Logging

Use a structured JSON logger. Every scan decision should be logged with:
- Timestamp
- Package name and version
- Verdict (clean/suspicious/malicious/error)
- GNN score
- Rules matched (if any)
- Decision path
- Scan time in milliseconds
- Whether result was cached

Example log line:
```json
{"timestamp":"2026-05-05T10:30:15Z","event":"scan_complete","package":"evil-pkg@1.0.0","verdict":"malicious","gnn_score":0.87,"rules":["CRIT_INSTALL_HOOK_NETWORK"],"decision":"GNN high confidence + CRITICAL rule","scan_ms":2340,"cached":false}
```

Also log:
- Proxy startup with config summary
- Every blocked package (separate BLOCK log for easy filtering)
- Scanner health status changes (reachable → unreachable, unreachable → reachable)
- Cache hit rate every 100 requests

### The Block Response

When a malicious package is blocked, the npm client receives a 403 response. npm will display the error message to the developer. Make it informative:

```
HTTP 403 Forbidden

{
  "error": "BLOCKED by SupplyGuard",
  "package": "evil-pkg@1.0.0",
  "verdict": "malicious",
  "confidence": 0.94,
  "evidence": [
    "postinstall hook decodes base64 payload (install.js:47)",
    "outbound HTTP request to non-registry domain (install.js:52)",
    "CRITICAL rule matched: CRIT_INSTALL_HOOK_NETWORK"
  ],
  "decision": "GNN high confidence (0.87) + CRITICAL behavioral rule match",
  "info": "This package was identified as malicious and has been blocked to protect your system. If you believe this is a false positive, contact your security team."
}
```

npm will print something like:
```
npm ERR! 403 Forbidden - GET http://localhost:4873/evil-pkg/-/evil-pkg-1.0.0.tgz
npm ERR! BLOCKED by SupplyGuard: evil-pkg@1.0.0 identified as malicious (confidence: 0.94)
```

### URL Parsing for npm Registry Requests

This is where most proxy bugs happen. npm's URL patterns:

```
# Regular package metadata
GET /express                          → metadata for "express"
GET /express/4.18.2                   → metadata for express@4.18.2

# Regular package tarball
GET /express/-/express-4.18.2.tgz    → tarball download

# Scoped package metadata
GET /@babel%2fcore                    → metadata for "@babel/core" (URL-encoded)
GET /@babel/core                      → some npm versions don't encode

# Scoped package tarball
GET /@babel/core/-/core-7.24.0.tgz   → tarball for @babel/core@7.24.0

# Other endpoints
GET /-/v1/search?text=express         → search
PUT /-/user/org.couchdb.user:*        → auth/login
GET /-/npm/v1/security/advisories     → audit
GET /-/ping                           → ping
```

Write a URL parser function that:
1. Identifies if a request is a tarball download (path contains `/-/` and ends with `.tgz`)
2. Extracts the package name (including scope if present) and version from tarball URLs
3. Passes everything else through as metadata

```javascript
function parseTarballUrl(path) {
  // Match: /{name}/-/{filename}-{version}.tgz
  // Match: /@{scope}/{name}/-/{filename}-{version}.tgz
  
  // Returns: { isTarball: true, name: '@scope/name', version: '1.0.0' }
  // Or: { isTarball: false } for non-tarball requests
}
```

Be careful with scoped packages — the `@scope/` part can be URL-encoded as `@scope%2f` in some npm versions. Handle both.

---

## Tests — proxy.test.js

Write integration tests that start both the FastAPI server and the proxy, then test the full flow.

**Test 1 — Clean package passes through:**
Configure npm to use the proxy. Run `npm pack is-number@7.0.0 --registry http://localhost:4873`. Assert the tarball is received successfully.

**Test 2 — Metadata requests pass through:**
Make a GET request to `http://localhost:4873/is-number`. Assert the response contains package metadata (versions, dist-tags, etc).

**Test 3 — Block response format:**
Create a mock malicious tarball, send it through the scanning flow, assert the proxy returns 403 with the correct error format.

**Test 4 — Cache works:**
Scan a package. Scan the same package again. Assert the second request returns faster (cache hit). Check that the cached result matches the original.

**Test 5 — Fail-open on scanner unreachable:**
Stop the FastAPI server. Make a tarball request through the proxy. Assert the tarball is forwarded anyway (not blocked) and a warning is logged.

**Test 6 — Scoped package URL parsing:**
Assert that `/@babel/core/-/core-7.24.0.tgz` correctly parses to name=`@babel/core`, version=`7.24.0`.
Assert that `/@babel%2fcore/-/core-7.24.0.tgz` also parses correctly.
Assert that `/express/-/express-4.18.2.tgz` parses to name=`express`, version=`4.18.2`.

Use `jest` for testing. Don't use mocha/chai.

---

## How to Run the Full System

Both servers need to be running simultaneously:

**Terminal 1 — Start the FastAPI scanning server:**
```bash
cd supplyguard/
venv\Scripts\python.exe -m uvicorn supplyguard.api.server:app --host 0.0.0.0 --port 8000
```

**Terminal 2 — Start the proxy:**
```bash
cd proxy/
npm install
node src/server.js
# Proxy listening on http://localhost:4873
# Upstream registry: https://registry.npmjs.org
# Scanner API: http://localhost:8000
```

**Terminal 3 — Test with npm:**
```bash
# Point npm at the proxy
npm config set registry http://localhost:4873/

# Install a clean package (should work normally)
npm install is-number

# Install a known malicious package (should be blocked)
# (use a test package you control, or a known-malicious one from the dataset)

# Reset npm registry when done
npm config set registry https://registry.npmjs.org/
```

---

## End-to-End Demo Script

Write a demo script `proxy/demo.sh` that:

1. Checks that the FastAPI server is running (curl http://localhost:8000/health)
2. Checks that the proxy is running (curl http://localhost:4873/-/ping)
3. Creates a temp directory with a fresh package.json
4. Sets the registry to the proxy
5. Installs a known clean package (is-number) — should succeed
6. Attempts to install a test malicious package — should be blocked with the evidence message
7. Prints "Demo complete" with the results
8. Cleans up the temp directory and resets the registry

This script is what you'll use for demo videos and live demos at events.

---

## Important Constraints

- The proxy is Node.js (JavaScript), NOT Python. It's a separate project from the Python codebase. It calls the Python FastAPI server via HTTP.
- Don't use Verdaccio. Write a lightweight proxy from scratch with Express. Verdaccio has limitations with async scanning and adds unnecessary complexity for the MVP.
- Don't implement auth/login endpoints. For the MVP, the proxy only handles anonymous read-only access to the public npm registry. Private registry support comes later.
- Don't implement HTTPS on the proxy itself. For local use, HTTP is fine. In production, you'd put it behind a reverse proxy (nginx, Caddy) that handles TLS.
- Don't implement rate limiting. Not needed for the MVP.
- Don't modify any Python code. The proxy is a new, separate Node.js project that calls the existing FastAPI server.
- Keep the total proxy codebase under 500 lines. This is a thin layer — most of the intelligence lives in the Python scanning server.

## Run Order

1. Write all proxy files. Don't run anything yet.
2. I'll review the code.
3. Install proxy dependencies: `cd proxy && npm install`
4. Start both servers (FastAPI in one terminal, proxy in another)
5. Run tests: `cd proxy && npx jest`
6. Run the demo script manually
7. If everything works, we record the demo video
