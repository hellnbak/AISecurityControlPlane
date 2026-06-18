#!/usr/bin/env bash
set -euo pipefail
curl -s http://127.0.0.1:8787/v1/control/events/ingest \
  -H 'content-type: application/json' \
  -d '{
    "events": [
      {
        "user": "steve@company.com",
        "device_id": "macbook-demo-001",
        "app": "claude.ai",
        "event_type": "paste",
        "decision": "allow",
        "requested_model": "auto-secure",
        "model_used": "claude-sonnet-4-6",
        "reasons": ["demo event"],
        "findings": []
      }
    ]
  }' | python -m json.tool
