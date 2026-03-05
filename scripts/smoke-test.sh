#!/usr/bin/env bash
set -euo pipefail

BASE_URL="http://127.0.0.1:3141"
PASS=0
FAIL=0

pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1 — $2"; FAIL=$((FAIL + 1)); }

cleanup() {
  echo ""
  echo "Cleaning up..."
  docker compose down --timeout 5 2>/dev/null || true
}
trap cleanup EXIT

echo "=== Sentinel Smoke Test ==="
echo ""

# 1. Build
echo "Step 1: Docker build"
if docker compose build executor 2>&1 | tail -3; then
  pass "docker compose build executor"
else
  fail "docker compose build" "build failed"
  exit 1
fi
echo ""

# 2. Start executor
echo "Step 2: Start executor"
docker compose up -d executor 2>&1

# Wait for healthy (max 30s)
echo "  Waiting for healthcheck..."
for i in $(seq 1 30); do
  STATUS=$(docker compose ps executor --format json 2>/dev/null | jq -r '.Health // .State' 2>/dev/null || echo "starting")
  if [ "$STATUS" = "healthy" ]; then
    break
  fi
  sleep 1
done

HEALTH=$(curl -sf "$BASE_URL/health" 2>/dev/null || echo "")
if echo "$HEALTH" | jq -e '.status == "ok"' >/dev/null 2>&1; then
  pass "GET /health -> {status: ok}"
else
  fail "GET /health" "got: $HEALTH"
  echo "Container logs:"
  docker compose logs executor 2>&1 | tail -20
  exit 1
fi
echo ""

# 3. Agent card
echo "Step 3: GET /agent-card"
CARD=$(curl -sf "$BASE_URL/agent-card" 2>/dev/null || echo "")
if echo "$CARD" | jq -e '.name == "Sentinel Executor"' >/dev/null 2>&1; then
  pass "GET /agent-card -> name=Sentinel Executor"
else
  fail "GET /agent-card" "got: $CARD"
fi
echo ""

# 4. Tools
echo "Step 4: GET /tools"
TOOLS=$(curl -sf "$BASE_URL/tools" 2>/dev/null || echo "")
TOOL_COUNT=$(echo "$TOOLS" | jq 'length' 2>/dev/null || echo "0")
if [ "$TOOL_COUNT" -eq 4 ]; then
  pass "GET /tools -> 4 tools registered"
else
  fail "GET /tools" "expected 4 tools, got $TOOL_COUNT"
fi
echo ""

# 5. Execute a read_file (auto-approved)
echo "Step 5: POST /execute (read_file, auto-approve)"
READ_ID=$(uuidgen | tr '[:upper:]' '[:lower:]')
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
MANIFEST=$(cat <<JSON
{
  "id": "$READ_ID",
  "timestamp": "$TIMESTAMP",
  "sessionId": "smoke-session",
  "tool": "read_file",
  "parameters": { "path": "/app/packages/types/package.json" }
}
JSON
)
RESULT=$(curl -s -X POST "$BASE_URL/execute" -H "Content-Type: application/json" -d "$MANIFEST" 2>/dev/null || echo "")
if echo "$RESULT" | jq -e '.success == true' >/dev/null 2>&1; then
  pass "POST /execute read_file -> success"
else
  fail "POST /execute read_file" "got: $RESULT"
fi
echo ""

# 6. Execute a blocked path
echo "Step 6: POST /execute (read_file .env, should block)"
BLOCK_ID=$(uuidgen | tr '[:upper:]' '[:lower:]')
BLOCK_TS=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
BLOCKED=$(cat <<JSON
{
  "id": "$BLOCK_ID",
  "timestamp": "$BLOCK_TS",
  "sessionId": "smoke-session",
  "tool": "read_file",
  "parameters": { "path": "/project/.env" }
}
JSON
)
BLOCK_RESULT=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE_URL/execute" -H "Content-Type: application/json" -d "$BLOCKED" 2>/dev/null || echo "000")
if [ "$BLOCK_RESULT" = "422" ]; then
  pass "POST /execute blocked path -> 422"
else
  fail "POST /execute blocked path" "expected 422, got $BLOCK_RESULT"
fi
echo ""

# Summary
echo "=== Results: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
echo "All smoke tests passed."
