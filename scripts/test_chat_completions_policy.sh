#!/usr/bin/env bash
set -euo pipefail
BASE_URL="${BASE_URL:-http://127.0.0.1:8787}"
# This should evaluate policy and then return provider_not_configured unless OPENAI_API_KEY is set.
curl -s -X POST "$BASE_URL/v1/chat/completions" \
  -H 'content-type: application/json' \
  -H 'x-secureai-user: steve@company.com' \
  -H 'x-secureai-app: curl-test' \
  -d '{"model":"openai-fast","messages":[{"role":"user","content":"hello from AISecurityControlPlane"}],"max_tokens":64}' | python -m json.tool
