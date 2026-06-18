#!/usr/bin/env bash
set -euo pipefail

curl -sS http://127.0.0.1:8787/v1/messages \
  -H 'content-type: application/json' \
  -H 'x-secureai-user: steve@company.com' \
  -H 'x-secureai-app: local-test' \
  -d '{
    "model": "auto-secure",
    "max_tokens": 256,
    "messages": [
      {"role":"user", "content":"Write a short security policy for safe Claude usage."}
    ]
  }' | python -m json.tool
