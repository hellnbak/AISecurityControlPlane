from __future__ import annotations

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Provider settings
    anthropic_api_key: str = ""
    anthropic_base_url: str = "https://api.anthropic.com"
    anthropic_version: str = "2023-06-01"
    openai_api_key: str = ""
    openai_base_url: str = "https://api.openai.com"
    gemini_api_key: str = ""
    gemini_base_url: str = "https://generativelanguage.googleapis.com"

    # Policy and local runtime
    policy_path: str = "policy.yaml"
    sqlite_path: str = "secureai_gateway.db"
    log_raw_prompts: bool = False
    org_id: str = "demo-org"

    # Scale-ready control plane settings. Leave blank for local-only MVP behavior.
    database_url: str = ""  # e.g. postgresql+psycopg://secureai:secureai@postgres:5432/secureai
    redis_url: str = ""  # e.g. redis://redis:6379/0
    secureai_signing_secret: str = "dev-only-change-me"
    secureai_gateway_public_url: str = "http://127.0.0.1:8787"


    # Identity / auth. Use disabled for local dev, optional while rolling out, required in production.
    auth_mode: str = "disabled"  # disabled | optional | required
    oidc_issuer: str = ""  # e.g. https://dev-123.okta.com/oauth2/default
    oidc_audience: str = ""  # e.g. api://secureai
    oidc_client_id: str = ""
    oidc_jwks_url: str = ""  # optional override; normally discovered from issuer
    oidc_groups_claim: str = "groups"
    oidc_email_claim: str = "email"
    oidc_jwks_cache_seconds: int = 3600
    oidc_leeway_seconds: int = 120

    # Device trust. optional lets local dev work; required blocks untrusted endpoints.
    device_trust_mode: str = "optional"  # disabled | optional | required
    device_enrollment_token: str = "dev-enroll-token-change-me"

    # JumpCloud enrichment/device posture. Read-only connector.
    jumpcloud_enable_enrichment: bool = False
    jumpcloud_api_key: str = ""
    jumpcloud_base_url: str = "https://console.jumpcloud.com"
    jumpcloud_org_id: str = ""

    # Admin UI/API. Keep write disabled in hardened deployments unless admin auth/device trust is enabled.
    admin_auth_mode: str = "disabled"  # disabled | required
    admin_groups: str = "security,ai-admins"
    admin_require_trusted_device: bool = False
    admin_enable_policy_write: bool = True

    # Async audit ingestion/event buffering
    audit_async_enabled: bool = True
    audit_queue_max_size: int = 5000
    endpoint_event_dir: str = "./data/endpoint-events"
    endpoint_event_spool_dir: str = "./data/audit-spool"

    # Budget reservation behavior
    budget_reservation_enabled: bool = True
    budget_default_reservation_usd: float = 0.05

    class Config:
        env_file = ".env"
        extra = "ignore"
