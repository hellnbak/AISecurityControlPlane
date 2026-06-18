#!/usr/bin/env bash
set -euo pipefail

curl -sS http://127.0.0.1:8787/v1/admin/overview | python -m json.tool
curl -sS http://127.0.0.1:8787/v1/admin/models | python -m json.tool
curl -sS http://127.0.0.1:8787/v1/admin/policy/validate \
  -H 'content-type: application/json' \
  -d "$(python - <<'PY'
import json
print(json.dumps({'policy_yaml': open('policy.yaml', encoding='utf-8').read()}))
PY
)" | python -m json.tool
