# Scanner API reference

FastAPI service defined in `korvyr/api/server.py`.

```bash
uvicorn korvyr.api.server:app --host 0.0.0.0 --port 8000
```

Interactive docs are served at `/docs` (Swagger) and `/redoc`.

The service has **no authentication**. It is intended for localhost or a trusted
internal network. Do not expose it publicly: `/scan/package` will fetch
arbitrary package names from the configured registry on a caller's behalf.

## Scan modes

Every scan response carries a `scan_mode` field:

| Value | Meaning |
|---|---|
| `hybrid` | A GNN checkpoint is loaded; `gnn_score` is a real probability in `[0, 1]` |
| `static-only` | No checkpoint; the verdict comes from rules and manifest analysis alone, and `gnn_score` is `-1.0` |

A response may additionally carry `"fallback": "rules_only"` when the service is
in hybrid mode but this particular package produced no model score (unparseable
sources, or an inference error).

---

## `GET /health`

```json
{
  "status": "healthy",
  "version": "0.1.0",
  "scan_mode": "static-only",
  "model_loaded": false,
  "model_checkpoint_loaded": false,
  "device": "cpu",
  "model_checkpoint": "models/gnn_v2_cuda.pt",
  "threshold_config": { "gnn_auto_pass": 0.35, "gnn_auto_block": 0.8 }
}
```

Always returns `200` while the process is up. Check `scan_mode` to distinguish a
degraded service from a healthy one — with `KORVYR_REQUIRE_GNN=true` the process
refuses to start rather than reporting `static-only`.

---

## `POST /scan/tarball`

Scan an uploaded package tarball. This is the endpoint the proxy uses.

**Request** — `multipart/form-data` with field `tarball`, filename ending in
`.tgz` or `.tar.gz`.

```bash
curl -F "tarball=@package.tgz" http://localhost:8000/scan/tarball
```

**Response** `200`:

```json
{
  "package_name": "package.tgz",
  "version": "unknown",
  "verdict": "malicious",
  "confidence": 0.92,
  "gnn_score": 0.87,
  "scan_mode": "hybrid",
  "decision_path": "v2 direct GNN block: score=0.870",
  "rules_matched": [
    {
      "rule_id": "CRIT_INSTALL_HOOK_EXEC",
      "severity": "critical",
      "description": "postinstall script runs shell command: curl ... | bash",
      "file_path": "package.json",
      "line_number": 0,
      "matched_snippet": "curl https://... | bash"
    }
  ],
  "evidence": ["GNN score: 0.870", "[CRITICAL] CRIT_INSTALL_HOOK_EXEC: ..."],
  "scan_time_ms": 412.7
}
```

**Errors**

| Status | Cause |
|---|---|
| `400` | Filename is not `.tgz`/`.tar.gz`, or the archive cannot be unpacked safely |
| `413` | Upload exceeds `KORVYR_MAX_UPLOAD_BYTES` (default 50 MiB) |

Extraction rejects archive members that would escape the temporary directory and
skips symlinks; a crafted tarball cannot write outside its scratch directory.
The scratch directory is always removed, including on error.

---

## `POST /scan/package`

Download `name@version` from `KORVYR_REGISTRY_URL` and scan it.

```bash
curl -X POST http://localhost:8000/scan/package \
     -H 'Content-Type: application/json' \
     -d '{"name": "is-number", "version": "7.0.0"}'
```

Scoped names work as-is (`{"name": "@babel/core", "version": "7.24.0"}`).

Response shape is identical to `/scan/tarball`, with `package_name` and
`version` set to the requested values.

**Errors**

| Status | Cause |
|---|---|
| `404` | The registry has no such package/version |
| `400` | The downloaded archive cannot be unpacked safely |
| `502`/`5xx` | Registry request failed |

---

## `POST /scan/lockfile`

Scan every pinned dependency in a `package-lock.json`. Handles both the v1
`dependencies` layout and the v2/v3 `packages` layout.

```bash
curl -F "lockfile=@package-lock.json" http://localhost:8000/scan/lockfile
```

**Response** `200`:

```json
{
  "total_packages": 42,
  "scan_time_seconds": 18.4,
  "scan_mode": "hybrid",
  "results": { "clean": 39, "suspicious": 2, "malicious": 1, "error": 0 },
  "flagged_packages": [ { "...": "full scan result per flagged package" } ]
}
```

Scans run on a thread pool sized by `KORVYR_MAX_WORKERS` and are memoised
per `name@version` for the lifetime of the process. Only `suspicious` and
`malicious` packages appear in `flagged_packages`; clean ones are counted only.

A large lockfile means one registry download per dependency — expect this call to
take a while and size your client timeout accordingly (`korvyr audit --timeout`).

---

## Verdicts

| Verdict | Meaning | Proxy behaviour |
|---|---|---|
| `clean` | No blocking evidence | Forwarded |
| `suspicious` | Evidence below the block thresholds; needs human review | **Forwarded**, logged |
| `malicious` | Blocking policy matched | Blocked with `403` |
| `error` | The scan itself failed; `error_msg` explains why | Fail-open forwards, fail-closed refuses |

`confidence` is a heuristic derived from the decision path, not a calibrated
probability. Treat it as an ordering hint, not as `P(malicious)`.
