#!/usr/bin/env bash
set -euo pipefail

FAKE_AWS_KEY="AK""IAABCDEFGHIJKLMNOP"
python - <<PY | curl -sS -i http://127.0.0.1:8787/v1/messages \
  -H 'content-type: application/json' \
  -H 'x-secureai-user: steve@example.com' \
  -H 'x-secureai-app: local-test' \
  --data-binary @-
import json, os
payload = {
    "model": "auto-secure",
    "max_tokens": 256,
    "messages": [{"role": "user", "content": f"Here is a fake AWS-looking key: {os.environ.get('FAKE_AWS_KEY', '$FAKE_AWS_KEY')}. Please store it."}],
}
print(json.dumps(payload))
PY
