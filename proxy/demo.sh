#!/usr/bin/env bash
# Korvyr end-to-end demonstration.
#
# Scans two LOCAL synthetic fixtures (tests/fixtures/) through the scanner API,
# then installs one small real package through the proxy. No malicious code is
# downloaded or executed at any point: the "malicious" fixture is a harmless
# stand-in that only matches Korvyr's install-hook rules.
#
# Usage:  ./proxy/demo.sh
# Requires: the scanner API on :8000 and the proxy on :4873 (docker compose up).

set -euo pipefail

API_URL="${KORVYR_API_URL:-http://localhost:8000}"
PROXY_URL="${KORVYR_PROXY_URL:-http://localhost:4873}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIXTURES="$REPO_ROOT/tests/fixtures"

log() { printf '\n=== %s ===\n' "$1"; }

log "1/4 Checking the scanner API at $API_URL"
if ! curl -fsS "$API_URL/health" >/dev/null; then
  echo "The Korvyr scanner API is not responding at $API_URL."
  echo "Start it with: docker compose up --build   (or: uvicorn korvyr.api.server:app)"
  exit 1
fi
curl -fsS "$API_URL/health"
echo
echo "If scan_mode is 'static-only' there is no GNN checkpoint loaded, and the"
echo "verdicts below come from static analysis alone. In 'hybrid' mode expect the"
echo "clean fixture to be flagged: these fixtures are a few lines long and sit far"
echo "outside the model's training distribution (see tests/fixtures/README.md)."

log "2/4 Scanning the clean fixture"
CLEAN_TGZ="$(mktemp -d)/clean-package.tgz"
tar -czf "$CLEAN_TGZ" -C "$FIXTURES" clean-package
curl -fsS -F "tarball=@$CLEAN_TGZ;filename=clean-package.tgz" "$API_URL/scan/tarball"
echo

log "3/4 Scanning the synthetic install-hook fixture"
HOOK_TGZ="$(mktemp -d)/install-hook.tgz"
tar -czf "$HOOK_TGZ" -C "$FIXTURES" malicious-install-hook
curl -fsS -F "tarball=@$HOOK_TGZ;filename=install-hook.tgz" "$API_URL/scan/tarball"
echo

log "4/4 Installing a real package through the proxy at $PROXY_URL"
if ! curl -fsS "$PROXY_URL/is-number" >/dev/null; then
  echo "Proxy not reachable at $PROXY_URL - skipping the install step."
  exit 0
fi

WORKDIR="$(mktemp -d)"
pushd "$WORKDIR" >/dev/null
echo '{ "name": "korvyr-demo", "version": "1.0.0", "private": true }' > package.json
# The registry override is scoped to this command only; the global npm config
# is never modified.
npm install --registry "$PROXY_URL" --no-audit --no-fund is-number@7.0.0
echo "Installed is-number@7.0.0 through Korvyr."
popd >/dev/null
rm -rf "$WORKDIR"

log "Demo complete"
echo "Proxy decisions are recorded in proxy/logs.jsonl and served at $PROXY_URL/api/logs"
