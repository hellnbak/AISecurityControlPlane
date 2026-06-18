#!/usr/bin/env bash
set -euo pipefail
curl -s http://127.0.0.1:8787/v1/web/evaluate \
  -H 'content-type: application/json' \
  -H 'x-secureai-user: steve@company.com' \
  -H 'x-secureai-app: claude.ai' \
  -d '{
    "event_type": "fetch",
    "url": "https://claude.ai/api/organizations/demo/chat_conversations/demo/completion",
    "method": "POST",
    "request_body": "{\"model\":\"claude-opus-4-8\",\"prompt\":\"write a memo\"}"
  }' | python -m json.tool
