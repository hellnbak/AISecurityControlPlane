#!/usr/bin/env bash
set -euo pipefail

GATEWAY_URL="${GATEWAY_URL:-http://127.0.0.1:8787}"

echo "== Provider health and fallback policy =="
curl -s "$GATEWAY_URL/v1/providers/health" | python -m json.tool

echo
echo "== Fallback attempt with local configuration =="
echo "If no provider API keys are configured, this should return secureai_provider_unavailable with attempted providers."
curl -s -X POST "$GATEWAY_URL/v1/chat/completions" \
  -H 'content-type: application/json' \
  -H 'x-secureai-user: failover-test@example.com' \
  -d '{"model":"auto-secure","messages":[{"role":"user","content":"Say hello in one short sentence."}],"max_tokens":64}' | python -m json.tool
