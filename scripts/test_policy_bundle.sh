#!/usr/bin/env bash
set -euo pipefail
curl -s http://127.0.0.1:8787/v1/control/policy/bundle \
  -H 'x-secureai-user: steve@company.com' \
  -H 'x-secureai-device: macbook-demo-001' \
  -H 'x-secureai-groups: security,engineering' | python -m json.tool
