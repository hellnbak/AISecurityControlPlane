#!/usr/bin/env bash
set -euo pipefail
GATEWAY="${SECUREAI_GATEWAY:-http://127.0.0.1:8787}"
USER_EMAIL="${SECUREAI_USER:-steve@example.com}"
DEVICE_ID="${SECUREAI_DEVICE_ID:-demo-device}"
DEVICE_TOKEN="${SECUREAI_DEVICE_TOKEN:-}"
BEARER_TOKEN="${SECUREAI_BEARER_TOKEN:-}"

headers=(
  -H "x-secureai-user: $USER_EMAIL"
  -H "x-secureai-device: $DEVICE_ID"
  -H "x-secureai-groups: security,engineering"
)
if [[ -n "$DEVICE_TOKEN" ]]; then
  headers+=( -H "x-secureai-device-token: $DEVICE_TOKEN" )
fi
if [[ -n "$BEARER_TOKEN" ]]; then
  headers+=( -H "authorization: Bearer $BEARER_TOKEN" )
fi

curl -sS "$GATEWAY/v1/control/identity/me" "${headers[@]}" | python -m json.tool
