#!/usr/bin/env bash
# brig·id leaf — load the production secrets from OpenBao into Docker Swarm.
#
# Creates the `brigid_master_key` Docker secret that deploy/compose.yaml expects,
# reading the value from OpenBao (KV v2) instead of a human pasting it by hand.
# Needs only bash, curl and jq on the host: no bao/vault CLI.
#
# Usage (on the Swarm manager, before `docker stack deploy`):
#   deploy/load-secrets.sh           # create the Docker secret if it is missing
#   deploy/load-secrets.sh --check   # only check that OpenBao serves a valid key
#
# Authentication, first match wins:
#   BAO_TOKEN                          an existing token (not revoked at the end)
#   BAO_ROLE_ID_FILE/BAO_SECRET_ID_FILE  AppRole credentials, files readable only by
#                                      the operator (default /etc/brigid/bao-role-id
#                                      and /etc/brigid/bao-secret-id)
#
# Settings (environment, all optional):
#   BAO_ADDR     https://bao.baxyz.dev:8200 (on the tailnet only: the host must run Tailscale)
#   BAO_MOUNT    kv
#   BAO_PATH     prod/brig-id/leaf-1
#   BAO_FIELD    BRIGID_MASTER_KEY
#   SECRET_NAME  brigid_master_key
#
# Swarm secrets are immutable and in use by the running service: when the secret
# already exists this script leaves it alone. Rotating the master key is a separate
# procedure (re-encrypt the database with `leaf rotate-key`, then swap the secret).
set -euo pipefail

BAO_ADDR="${BAO_ADDR:-https://bao.baxyz.dev:8200}"
BAO_MOUNT="${BAO_MOUNT:-kv}"
BAO_PATH="${BAO_PATH:-prod/brig-id/leaf-1}"
BAO_FIELD="${BAO_FIELD:-BRIGID_MASTER_KEY}"
BAO_ROLE_ID_FILE="${BAO_ROLE_ID_FILE:-/etc/brigid/bao-role-id}"
BAO_SECRET_ID_FILE="${BAO_SECRET_ID_FILE:-/etc/brigid/bao-secret-id}"
SECRET_NAME="${SECRET_NAME:-brigid_master_key}"

check_only=false
case "${1:-}" in
  --check) check_only=true ;;
  "") ;;
  *) echo "usage: $0 [--check]" >&2; exit 2 ;;
esac

die() { echo "✗ $*" >&2; exit 1; }

for cmd in curl jq; do
  command -v "$cmd" >/dev/null 2>&1 || die "$cmd is required"
done

# ── Log in ────────────────────────────────────────────────────────────────────
token="${BAO_TOKEN:-}"
revoke=false
if [ -z "$token" ]; then
  [ -r "$BAO_ROLE_ID_FILE" ] && [ -r "$BAO_SECRET_ID_FILE" ] \
    || die "no BAO_TOKEN and AppRole files not readable: $BAO_ROLE_ID_FILE, $BAO_SECRET_ID_FILE"
  login_body="$(jq -n --rawfile r "$BAO_ROLE_ID_FILE" --rawfile s "$BAO_SECRET_ID_FILE" \
    '{role_id: ($r | rtrimstr("\n")), secret_id: ($s | rtrimstr("\n"))}')"
  token="$(curl -fsS --max-time 15 -X POST --data @- "$BAO_ADDR/v1/auth/approle/login" \
    <<<"$login_body" | jq -er '.auth.client_token')" \
    || die "AppRole login to $BAO_ADDR failed (Tailscale up? secret-id expired?)"
  revoke=true
fi

cleanup() {
  if $revoke; then
    curl -fsS --max-time 10 -X POST -H "X-Vault-Token: $token" \
      "$BAO_ADDR/v1/auth/token/revoke-self" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

# ── Read the key ──────────────────────────────────────────────────────────────
key="$(curl -fsS --max-time 15 -H "X-Vault-Token: $token" \
  "$BAO_ADDR/v1/$BAO_MOUNT/data/$BAO_PATH" | jq -er --arg f "$BAO_FIELD" '.data.data[$f] // empty')" \
  || die "cannot read field $BAO_FIELD at $BAO_MOUNT/$BAO_PATH (missing, or denied by policy)"

# Same rule as leaf's own startup check: a 64-character hex string (32 bytes).
[[ "$key" =~ ^[0-9a-fA-F]{64}$ ]] \
  || die "$BAO_MOUNT/$BAO_PATH#$BAO_FIELD is not a 64-character hex string (32 bytes)"

echo "✓ OpenBao serves a valid master key ($BAO_MOUNT/$BAO_PATH#$BAO_FIELD)"
$check_only && exit 0

# ── Create the Docker secret ──────────────────────────────────────────────────
if docker secret inspect "$SECRET_NAME" >/dev/null 2>&1; then
  echo "✓ Docker secret $SECRET_NAME already exists, left unchanged"
  exit 0
fi

printf '%s' "$key" | docker secret create "$SECRET_NAME" - >/dev/null
echo "✓ Docker secret $SECRET_NAME created from OpenBao"
