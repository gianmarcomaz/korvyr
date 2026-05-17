#!/bin/bash

# SupplyGuard Proxy End-to-End Demo Script

echo "==============================================="
echo "   SupplyGuard Proxy - E2E Demonstration       "
echo "==============================================="
echo ""

# 1. Check if FastAPI server is running
echo "[1/4] Checking backend scanner..."
curl -s http://localhost:8000/health > /dev/null
if [ $? -ne 0 ]; then
  echo "❌ Error: FastAPI scanner is not running at http://localhost:8000"
  echo "Please start it with: venv\Scripts\python.exe -m uvicorn supplyguard.api.server:app --host 0.0.0.0 --port 8000"
  exit 1
fi
echo "✅ Backend scanner is running."

# 2. Check if proxy is running
echo "[2/4] Checking proxy server..."
# We just test a metadata endpoint since there is no explicit ping
curl -s http://localhost:4873/is-number > /dev/null
if [ $? -ne 0 ]; then
  echo "❌ Error: Proxy server is not running at http://localhost:4873"
  echo "Please start it with: cd proxy && npm start"
  exit 1
fi
echo "✅ Proxy server is running."

# 3. Setup Temp Directory
echo "[3/4] Setting up isolated npm environment..."
TEMP_DIR=$(mktemp -d)
cd $TEMP_DIR
echo "{ \"name\": \"demo\", \"version\": \"1.0.0\" }" > package.json
# Set registry to our proxy
npm config set registry http://localhost:4873/
echo "✅ Configured npm to use http://localhost:4873/"

# 4. Run the demo
echo ""
echo "==============================================="
echo "   Starting Interception Tests                 "
echo "==============================================="
echo ""

echo "▶ TEST 1: Installing a known clean package (is-number@7.0.0)"
echo "  npm install is-number@7.0.0"
npm install is-number@7.0.0
if [ $? -eq 0 ]; then
  echo "✅ Success: Clean package installed normally."
else
  echo "❌ Failed to install clean package."
fi
echo ""

# Note: In a real demo, we'd have a malicious package published to the registry,
# or we can use a known malicious package from the wild if it hasn't been pulled.
# Since we don't want to actually execute malicious code, we can just trigger the proxy
# by asking it for a package we *mocked* or we can just try to fetch a known bad package.
# For demo purposes, we'll try to fetch a package that SupplyGuard would flag.
# If there is no live malicious package, the mock tests handle it. 

echo "▶ TEST 2: Simulating malicious package interception"
echo "  Note: For live demos, we attempt to download a package the scanner flags."
echo "  (Requires a test malicious package to be accessible via npm)"
echo ""
echo "  Let's simulate the block response:"
echo "  npm ERR! 403 Forbidden - GET http://localhost:4873/evil-test-pkg/-/evil-test-pkg-1.0.0.tgz"
echo "  npm ERR! BLOCKED by SupplyGuard: evil-test-pkg@1.0.0 identified as malicious"

echo ""
echo "==============================================="
echo "   Demo Complete                               "
echo "==============================================="

# Cleanup
echo "Cleaning up..."
npm config set registry https://registry.npmjs.org/
cd - > /dev/null
rm -rf $TEMP_DIR
echo "✅ Restored npm registry to default."
