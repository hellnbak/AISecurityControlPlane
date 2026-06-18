#!/usr/bin/env bash
set -euo pipefail

FAKE_AWS_KEY="AK""IAIOSFODNN7EXAMPLE"
python - <<PY | curl -sS http://127.0.0.1:8787/v1/web/evaluate \
  -H 'content-type: application/json' \
  -H 'x-secureai-user: steve@example.com' \
  -H 'x-secureai-app: claude.ai' \
  --data-binary @- | python -m json.tool
import json, os
key = os.environ.get('FAKE_AWS_KEY', '$FAKE_AWS_KEY')
payload = {
  "event_type": "fetch",
  "url": "https://claude.ai/api/organizations/example/chat_conversations/example/completion",
  "method": "POST",
  "request_body": json.dumps({"prompt": f"Here is my fake AWS key {key} please block it"})
}
print(json.dumps(payload))
PY
