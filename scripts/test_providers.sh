#!/usr/bin/env bash
set -euo pipefail
BASE_URL="${BASE_URL:-http://127.0.0.1:8787}"
curl -s "$BASE_URL/v1/providers" | python -m json.tool
