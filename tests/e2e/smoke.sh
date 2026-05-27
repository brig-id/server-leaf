#!/usr/bin/env bash
# tests/e2e/smoke.sh — brig·id leaf smoke test suite
#
# Requires a running leaf instance. Set BASE_URL to override the default.
#
# Usage:
#   BASE_URL=http://localhost:8080 bash tests/e2e/smoke.sh
#
# Exit code: 0 = all checks passed, 1 = at least one failure.

set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8080}"
PASS=0
FAIL=0

# Colour codes (disabled when not a tty).
if [ -t 1 ]; then
  GREEN="\033[0;32m"
  RED="\033[0;31m"
  RESET="\033[0m"
else
  GREEN="" RED="" RESET=""
fi

check() {
  local label="$1"
  local url="$2"
  local expected_status="${3:-200}"
  local jq_filter="${4:-.}"
  local method="${5:-GET}"

  local response
  response=$(curl -sS -w '\n%{http_code}' -X "$method" "$url" 2>&1) || {
    echo -e "${RED}FAIL${RESET} ${label}: curl failed"
    FAIL=$((FAIL + 1))
    return
  }

  local body http_status
  body=$(echo "$response" | head -n -1)
  http_status=$(echo "$response" | tail -n 1)

  if [ "$http_status" != "$expected_status" ]; then
    echo -e "${RED}FAIL${RESET} ${label}: expected HTTP ${expected_status}, got ${http_status}"
    FAIL=$((FAIL + 1))
    return
  fi

  if [ "$jq_filter" != "." ]; then
    if ! echo "$body" | jq -e "$jq_filter" > /dev/null 2>&1; then
      echo -e "${RED}FAIL${RESET} ${label}: JSON assertion '${jq_filter}' failed"
      FAIL=$((FAIL + 1))
      return
    fi
  fi

  echo -e "${GREEN}PASS${RESET} ${label}"
  PASS=$((PASS + 1))
}

# check_one_of: like check() but accepts a space-separated list of valid HTTP
# status codes (e.g. "415 422" when either status is acceptable).
check_one_of() {
  local label="$1"
  local url="$2"
  local allowed_statuses="$3"
  local jq_filter="${4:-.}"
  local method="${5:-GET}"

  local response
  response=$(curl -sS -w '\n%{http_code}' -X "$method" "$url" 2>&1) || {
    echo -e "${RED}FAIL${RESET} ${label}: curl failed"
    FAIL=$((FAIL + 1))
    return
  }

  local body http_status
  body=$(echo "$response" | head -n -1)
  http_status=$(echo "$response" | tail -n 1)

  local matched=false
  for s in $allowed_statuses; do
    if [ "$http_status" = "$s" ]; then
      matched=true
      break
    fi
  done

  if ! $matched; then
    echo -e "${RED}FAIL${RESET} ${label}: expected one of [${allowed_statuses}], got ${http_status}"
    FAIL=$((FAIL + 1))
    return
  fi

  echo -e "${GREEN}PASS${RESET} ${label} (HTTP ${http_status})"
  PASS=$((PASS + 1))
}

echo "Running smoke tests against ${BASE_URL}"
echo "---"

# Health & readiness
check "GET /health → 200 + status=ok"  "${BASE_URL}/health"  "200"  '.status == "ok"'
check "GET /ready  → 200"              "${BASE_URL}/ready"   "200"

# Discovery endpoints
check "GET /.well-known/openid-configuration" \
  "${BASE_URL}/.well-known/openid-configuration" "200" \
  '.issuer and .jwks_uri and .authorization_endpoint'

check "GET /.well-known/jwks.json — has keys array" \
  "${BASE_URL}/.well-known/jwks.json" "200" \
  '.keys | length > 0'

check "GET /.well-known/did.json — has id field" \
  "${BASE_URL}/.well-known/did.json" "200" \
  '.id | startswith("did:web:")'

# Auth endpoints — missing body should return 415 (Unsupported Media Type) or 422
check_one_of "POST /auth/register/begin without body → 415/422" \
  "${BASE_URL}/auth/register/begin" "415 422" "." "POST"

# Logout without token → 401
check "POST /auth/logout without Bearer → 401" \
  "${BASE_URL}/auth/logout" "401" "." "POST"

# Security headers present
HEADERS=$(curl -sS -I "${BASE_URL}/health" 2>&1) || {
  echo -e "${RED}FAIL${RESET} Security headers: curl failed"
  FAIL=$((FAIL + 1))
}
if echo "$HEADERS" | grep -qi "x-content-type-options: nosniff"; then
  echo -e "${GREEN}PASS${RESET} Security header: X-Content-Type-Options"
  PASS=$((PASS + 1))
else
  echo -e "${RED}FAIL${RESET} Security header: X-Content-Type-Options missing"
  FAIL=$((FAIL + 1))
fi

if echo "$HEADERS" | grep -qi "x-frame-options: deny"; then
  echo -e "${GREEN}PASS${RESET} Security header: X-Frame-Options"
  PASS=$((PASS + 1))
else
  echo -e "${RED}FAIL${RESET} Security header: X-Frame-Options missing"
  FAIL=$((FAIL + 1))
fi

echo "---"
echo "Results: ${PASS} passed, ${FAIL} failed"

[ "$FAIL" -eq 0 ]
