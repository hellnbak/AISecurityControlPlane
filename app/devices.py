from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


def sha256_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@dataclass
class DeviceTrustResult:
    trusted: bool
    device_id: str | None
    user: str | None
    reason: str
    posture: dict[str, Any]


class DeviceTrustService:
    """Device enrollment and trust checks.

    MVP model:
      * A bootstrap enrollment token lets an endpoint enroll once.
      * The gateway issues a high-entropy device token.
      * Subsequent calls include X-AISecurityControlPlane-Device and X-AISecurityControlPlane-Device-Token.
      * The server stores only a SHA-256 token hash.

    Production upgrade path:
      * replace bearer device token with mTLS, TPM/Secure Enclave attestation, or
        signed per-request device proofs from an MDM-issued cert.
    """

    def __init__(self, store, *, enrollment_token: str = "", trust_mode: str = "optional"):
        self.store = store
        self.enrollment_token = enrollment_token
        self.trust_mode = (trust_mode or "optional").lower()

    def enroll(
        self,
        *,
        provided_enrollment_token: str,
        user: str,
        device_name: str | None = None,
        platform: str | None = None,
        serial_number: str | None = None,
        mdm_provider: str | None = None,
        mdm_device_id: str | None = None,
        public_key_pem: str | None = None,
        posture: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if not self.enrollment_token:
            raise PermissionError("Device enrollment token is not configured")
        if not hmac.compare_digest(str(provided_enrollment_token or ""), self.enrollment_token):
            raise PermissionError("Invalid device enrollment token")

        device_id = "dev_" + secrets.token_urlsafe(18).replace("-", "_")
        device_token = "sdv_" + secrets.token_urlsafe(32)
        now = datetime.now(timezone.utc)
        self.store.upsert_device(
            device_id=device_id,
            user=user,
            device_token_hash=sha256_token(device_token),
            status="trusted",
            device_name=device_name,
            platform=platform,
            serial_number=serial_number,
            mdm_provider=mdm_provider,
            mdm_device_id=mdm_device_id,
            public_key_pem=public_key_pem,
            posture=posture or {},
            enrolled_at=now,
            last_seen_at=now,
        )
        return {
            "device_id": device_id,
            "device_token": device_token,
            "status": "trusted",
            "user": user,
            "device_name": device_name,
            "platform": platform,
            "enrolled_at": now.isoformat(),
            "warning": "Store device_token securely. It is only returned at enrollment time.",
        }

    def verify(self, *, device_id: str | None, device_token: str | None, user: str | None = None) -> DeviceTrustResult:
        if self.trust_mode == "disabled":
            return DeviceTrustResult(True, device_id, user, "Device trust disabled", {})
        if not device_id or not device_token:
            return DeviceTrustResult(False, device_id, user, "Missing device credential", {})
        row = self.store.get_device(device_id)
        if not row:
            return DeviceTrustResult(False, device_id, user, "Unknown device", {})
        if row.get("status") != "trusted":
            return DeviceTrustResult(False, device_id, row.get("user"), f"Device status is {row.get('status')}", row.get("posture") or {})
        if user and row.get("user") and str(row.get("user")).lower() != str(user).lower():
            return DeviceTrustResult(False, device_id, row.get("user"), "Device is not enrolled to this user", row.get("posture") or {})
        expected = str(row.get("device_token_hash") or "")
        actual = sha256_token(str(device_token or ""))
        if not hmac.compare_digest(expected, actual):
            return DeviceTrustResult(False, device_id, row.get("user"), "Invalid device token", row.get("posture") or {})
        self.store.touch_device(device_id)
        return DeviceTrustResult(True, device_id, row.get("user"), "Device credential verified", row.get("posture") or {})
