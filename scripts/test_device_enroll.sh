#!/usr/bin/env bash
set -euo pipefail
GATEWAY="${SECUREAI_GATEWAY:-http://127.0.0.1:8787}"
ENROLL_TOKEN="${SECUREAI_ENROLLMENT_TOKEN:-change-me}"
USER_EMAIL="${SECUREAI_USER:-steve@example.com}"

curl -sS -X POST "$GATEWAY/v1/control/device/enroll" \
  -H "content-type: application/json" \
  -H "x-secureai-enrollment-token: $ENROLL_TOKEN" \
  -d "{\"user\":\"$USER_EMAIL\",\"device_name\":\"Demo MacBook\",\"platform\":\"macOS\",\"mdm_provider\":\"JumpCloud\",\"posture\":{\"managed\":true,\"disk_encrypted\":true}}" \
  | python -m json.tool
