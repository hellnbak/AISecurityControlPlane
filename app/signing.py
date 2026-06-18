from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone
from typing import Any


def canonical_json(payload: Any) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(payload: Any) -> str:
    return hashlib.sha256(canonical_json(payload)).hexdigest()


def hmac_sha256(secret: str, payload: Any) -> str:
    return hmac.new(secret.encode("utf-8"), canonical_json(payload), hashlib.sha256).hexdigest()


def signed_envelope(payload: dict[str, Any], secret: str, *, key_id: str = "local-dev") -> dict[str, Any]:
    envelope = {
        "payload": payload,
        "signature": {
            "alg": "HS256",
            "key_id": key_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "value": hmac_sha256(secret, payload),
        },
    }
    return envelope


def verify_envelope(envelope: dict[str, Any], secret: str) -> bool:
    try:
        payload = envelope["payload"]
        expected = hmac_sha256(secret, payload)
        received = str(envelope.get("signature", {}).get("value") or "")
        return hmac.compare_digest(expected, received)
    except Exception:
        return False
