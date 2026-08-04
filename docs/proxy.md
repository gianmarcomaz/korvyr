# npm registry proxy

A Node.js registry mirror that screens tarballs through the Korvyr scanner
before forwarding them to the npm client. Source: `proxy/`.

```
npm install <pkg>
     |
     v
korvyr-proxy :4873
     |-- metadata request  -> forwarded to the upstream registry unchanged
     |
     `-- tarball request
            |-- cached verdict?  -> reuse it
            |-- otherwise: download, POST to /scan/tarball, cache the verdict
            |
            |-- clean       -> forward
            |-- suspicious  -> forward, log the verdict
            |-- malicious   -> 403, install fails
            `-- unscannable -> KORVYR_FAIL_MODE decides (default: forward)
```

## Run it

```bash
cd proxy
npm ci
KORVYR_SCAN_API_URL=http://localhost:8000 npm start
```

Or as part of the stack: `docker compose up --build`.

Point npm at it for a single command rather than editing your global config:

```bash
npm install --registry http://localhost:4873 is-number@7.0.0
```

A project-local `.npmrc` (`registry=http://localhost:4873/`) works too. `.npmrc`
is git-ignored in this repository so a local override is never committed.

## Configuration

All variables are documented in `.env.example`. The ones specific to the proxy:

| Variable | Default | Meaning |
|---|---|---|
| `KORVYR_PROXY_PORT` | `4873` | Listen port |
| `KORVYR_SCAN_API_URL` | `http://localhost:8000` | Scanner API base URL |
| `KORVYR_REGISTRY_URL` | `https://registry.npmjs.org` | Upstream registry |
| `KORVYR_SCAN_TIMEOUT` | `30000` | Scan timeout in ms |
| `KORVYR_FAIL_MODE` | `open` | `open` forwards unscannable packages, `closed` refuses them |
| `KORVYR_REDIS_URL` | *(empty)* | Shared verdict cache; empty = in-memory only |
| `KORVYR_CACHE_TTL` | `86400` | Verdict lifetime in seconds |
| `KORVYR_MAX_TARBALL_SIZE` | `52428800` | Largest tarball buffered for scanning |
| `KORVYR_LOG_LEVEL` | `info` | `debug` \| `info` \| `warn` \| `error` |
| `KORVYR_LOG_FILE` | `proxy/logs.jsonl` | JSONL decision log |

## Deployment limitations

Read these before putting the proxy in front of anything that matters.

**It fails open by default.** If the scanner is unreachable, times out, returns
an error, or the tarball exceeds `KORVYR_MAX_TARBALL_SIZE`, the default
configuration **forwards the package unscanned** and writes a `fail_open` warning
to the log. A scanner outage silently removes the control while installs keep
succeeding. If you deploy this, alert on `event: "fail_open"`.

`KORVYR_FAIL_MODE=closed` makes those cases return `503` instead. That mode
breaks every install whenever the scanner is down, and it has not been evaluated
at scale.

**Only `malicious` blocks.** `suspicious` packages are forwarded. They are
recorded in the log and shown in the dashboard, but nothing stops the install.

**Verdicts are cached by `name@version`.** Within `KORVYR_CACHE_TTL` a
republished version is served from the cached verdict. Shorten the TTL if that
matters to you.

**Tarballs are buffered in memory.** Each concurrent scan holds a full tarball in
memory, bounded by `KORVYR_MAX_TARBALL_SIZE` (50 MiB default) per request. Size
your concurrency accordingly.

**No authentication and no TLS.** The proxy is a plain HTTP service intended for
localhost or a trusted network. It forwards client headers upstream, including
registry auth tokens, so pointing it at a private registry means it sees those
credentials. Terminate TLS in front of it if you deploy it beyond localhost.

**Metadata is passed through unmodified.** The proxy screens tarballs only; it
does not rewrite version metadata, so npm's resolution is unchanged.

## Decision log

Each line in `proxy/logs.jsonl` is one JSON object. Events:

| `event` | Meaning |
|---|---|
| `scan_complete` | A verdict was produced (or reused from cache) |
| `block` | A malicious verdict resulted in a `403` |
| `fail_open` | A package was forwarded **without** being scanned |
| `fail_closed` | A package was refused because it could not be scanned |
| `scan_skipped` | Tarball exceeded the size limit |

The log is also served at `GET /api/logs` (newest first) and rendered by the
dashboard. It is append-only and unbounded — rotate it yourself for long runs.

## Tests

```bash
cd proxy && npm test
```

The suite covers URL parsing (scoped, unscoped, and percent-encoded), metadata
pass-through, the clean/suspicious/malicious paths, cache reuse, and both fail
modes. Upstream requests and the scanner are mocked, so no network access and no
real package downloads are involved.
