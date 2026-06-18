from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

import httpx
import jwt
from fastapi import HTTPException, Request
from jwt import PyJWKClient

from .settings import Settings


@dataclass
class IdentityContext:
    authenticated: bool
    user: str
    subject: str | None = None
    email: str | None = None
    groups: list[str] = field(default_factory=list)
    provider: str = "local"
    claims: dict[str, Any] = field(default_factory=dict)
    device_trusted: bool = False
    device_id: str | None = None
    device_reason: str | None = None
    device_posture: dict[str, Any] = field(default_factory=dict)
    jumpcloud: dict[str, Any] = field(default_factory=dict)


class OIDCVerifier:
    """Validates Okta/OIDC JWTs using JWKS.

    Works with Okta custom authorization servers and other OIDC providers that expose
    a JWKS endpoint. PyJWKClient handles key lookup by kid and caches key material.
    """

    def __init__(self, settings: Settings):
        self.settings = settings
        self._jwks_client: PyJWKClient | None = None
        self._jwks_uri: str | None = settings.oidc_jwks_url or None
        self._discovery_loaded_at = 0.0

    def enabled(self) -> bool:
        return bool(self.settings.oidc_issuer and (self.settings.oidc_audience or self.settings.oidc_client_id))

    async def _discover(self) -> str:
        if self._jwks_uri and (time.time() - self._discovery_loaded_at) < self.settings.oidc_jwks_cache_seconds:
            return self._jwks_uri
        if self.settings.oidc_jwks_url:
            self._jwks_uri = self.settings.oidc_jwks_url
            self._discovery_loaded_at = time.time()
            return self._jwks_uri
        issuer = self.settings.oidc_issuer.rstrip("/")
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(f"{issuer}/.well-known/openid-configuration")
            response.raise_for_status()
            doc = response.json()
        jwks_uri = doc.get("jwks_uri")
        if not jwks_uri:
            raise HTTPException(status_code=500, detail="OIDC discovery did not include jwks_uri")
        self._jwks_uri = jwks_uri
        self._discovery_loaded_at = time.time()
        return jwks_uri

    async def verify_bearer(self, token: str) -> IdentityContext:
        if not self.enabled():
            raise HTTPException(status_code=500, detail="OIDC is not configured")
        jwks_uri = await self._discover()
        if not self._jwks_client or self._jwks_client.uri != jwks_uri:
            self._jwks_client = PyJWKClient(jwks_uri)
        try:
            signing_key = self._jwks_client.get_signing_key_from_jwt(token)
            audience = self.settings.oidc_audience or self.settings.oidc_client_id
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                audience=audience,
                issuer=self.settings.oidc_issuer.rstrip("/"),
                leeway=self.settings.oidc_leeway_seconds,
                options={"verify_aud": bool(audience)},
            )
        except Exception as exc:
            raise HTTPException(status_code=401, detail=f"Invalid OIDC token: {type(exc).__name__}") from exc

        if self.settings.oidc_client_id:
            cid = claims.get("cid") or claims.get("azp") or claims.get("client_id")
            # Do not require cid if the token does not carry it; Okta custom AS audience-only validation is common.
            if cid and cid != self.settings.oidc_client_id:
                raise HTTPException(status_code=401, detail="OIDC token client id mismatch")

        groups_raw = claims.get(self.settings.oidc_groups_claim) or []
        if isinstance(groups_raw, str):
            groups = [groups_raw]
        elif isinstance(groups_raw, list):
            groups = [str(g) for g in groups_raw]
        else:
            groups = []
        email = claims.get(self.settings.oidc_email_claim) or claims.get("preferred_username")
        user = str(email or claims.get("sub") or "unknown")
        return IdentityContext(
            authenticated=True,
            user=user,
            subject=str(claims.get("sub") or ""),
            email=str(email) if email else None,
            groups=groups,
            provider="oidc",
            claims={k: v for k, v in claims.items() if k not in {"nonce", "at_hash"}},
        )


class JumpCloudClient:
    """Minimal JumpCloud enrichment connector.

    The connector is intentionally read-only. It can enrich a valid OIDC identity with
    JumpCloud user/device information and can optionally be used to enforce trusted-device
    posture when your org uses JumpCloud for MDM/device inventory.
    """

    def __init__(self, settings: Settings):
        self.settings = settings

    def enabled(self) -> bool:
        return bool(self.settings.jumpcloud_api_key and self.settings.jumpcloud_enable_enrichment)

    def _headers(self) -> dict[str, str]:
        headers = {"x-api-key": self.settings.jumpcloud_api_key, "content-type": "application/json"}
        if self.settings.jumpcloud_org_id:
            headers["x-org-id"] = self.settings.jumpcloud_org_id
        return headers

    async def _get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        base = self.settings.jumpcloud_base_url.rstrip("/")
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(f"{base}{path}", headers=self._headers(), params=params or {})
            response.raise_for_status()
            return response.json()

    async def find_user_by_email(self, email: str) -> dict[str, Any]:
        if not self.enabled() or not email:
            return {}
        # JumpCloud API shapes vary between v1/v2 resources. Try a small set of read-only lookups.
        candidates: list[dict[str, Any]] = []
        for path, params in [
            ("/api/systemusers", {"filter": f"email:$eq:{email}", "limit": 10}),
            ("/api/v2/systemusers", {"filter": f"email:$eq:{email}", "limit": 10}),
            ("/api/search/systemusers", {"searchTerm": email}),
        ]:
            try:
                data = await self._get(path, params)
                if isinstance(data, dict) and isinstance(data.get("results"), list):
                    candidates.extend(x for x in data["results"] if isinstance(x, dict))
                elif isinstance(data, list):
                    candidates.extend(x for x in data if isinstance(x, dict))
            except Exception:
                continue
        best = next((c for c in candidates if str(c.get("email") or "").lower() == email.lower()), None)
        if not best and candidates:
            best = candidates[0]
        if not best:
            return {}
        return {
            "id": best.get("id") or best.get("_id"),
            "email": best.get("email"),
            "username": best.get("username"),
            "activated": best.get("activated"),
            "suspended": best.get("suspended"),
            "mfa_enabled": best.get("mfa") or best.get("totp_enabled"),
        }

    async def find_system(self, *, serial_number: str | None = None, mdm_device_id: str | None = None, hostname: str | None = None) -> dict[str, Any]:
        if not self.enabled():
            return {}
        terms = [x for x in [serial_number, mdm_device_id, hostname] if x]
        if not terms:
            return {}
        candidates: list[dict[str, Any]] = []
        for term in terms:
            for path, params in [
                ("/api/systems", {"filter": f"serialNumber:$eq:{term}", "limit": 10}),
                ("/api/v2/systems", {"filter": f"serialNumber:$eq:{term}", "limit": 10}),
                ("/api/search/systems", {"searchTerm": term}),
            ]:
                try:
                    data = await self._get(path, params)
                    if isinstance(data, dict) and isinstance(data.get("results"), list):
                        candidates.extend(x for x in data["results"] if isinstance(x, dict))
                    elif isinstance(data, list):
                        candidates.extend(x for x in data if isinstance(x, dict))
                except Exception:
                    continue
        if not candidates:
            return {}
        best = candidates[0]
        return {
            "id": best.get("id") or best.get("_id"),
            "hostname": best.get("hostname") or best.get("displayName"),
            "serial_number": best.get("serialNumber"),
            "os": best.get("os") or best.get("osFamily"),
            "agent_bound": bool(best.get("agentBound") or best.get("active")),
        }


class IdentityService:
    def __init__(self, settings: Settings, device_service=None):
        self.settings = settings
        self.oidc = OIDCVerifier(settings)
        self.jumpcloud = JumpCloudClient(settings)
        self.device_service = device_service

    async def resolve(
        self,
        request: Request,
        *,
        header_user: str = "anonymous",
        header_groups: str = "",
        header_device_id: str = "unknown-device",
    ) -> IdentityContext:
        mode = (self.settings.auth_mode or "disabled").lower()
        auth_header = request.headers.get("authorization", "")
        context: IdentityContext | None = None

        if mode in {"required", "optional"} and auth_header.lower().startswith("bearer "):
            token = auth_header.split(" ", 1)[1].strip()
            context = await self.oidc.verify_bearer(token)
        elif mode == "required":
            raise HTTPException(status_code=401, detail="Bearer OIDC token required")
        else:
            groups = [g.strip() for g in header_groups.split(",") if g.strip()]
            context = IdentityContext(
                authenticated=False,
                user=header_user or "anonymous",
                email=header_user if "@" in (header_user or "") else None,
                groups=groups,
                provider="header-dev" if mode == "disabled" else "anonymous",
            )

        device_id = request.headers.get("x-secureai-device") or header_device_id
        device_token = request.headers.get("x-secureai-device-token")
        if self.device_service:
            trust = self.device_service.verify(device_id=device_id, device_token=device_token, user=context.user)
            context.device_trusted = trust.trusted
            context.device_id = trust.device_id
            context.device_reason = trust.reason
            context.device_posture = trust.posture
            if self.settings.device_trust_mode == "required" and not trust.trusted:
                raise HTTPException(status_code=403, detail=f"Trusted device required: {trust.reason}")
        else:
            context.device_id = device_id

        if self.jumpcloud.enabled() and context.email:
            jc_user = await self.jumpcloud.find_user_by_email(context.email)
            context.jumpcloud["user"] = jc_user
            if jc_user.get("suspended") is True:
                raise HTTPException(status_code=403, detail="JumpCloud user is suspended")
        return context
