from __future__ import annotations

import hashlib
import json
from pathlib import Path
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

import httpx
import yaml
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse

from .audit_pipeline import AuditPipeline
from .budget import BudgetService
from .devices import DeviceTrustService
from .identity import IdentityService
from .policy import PolicyEngine
from .providers import MultiProviderClient, ProviderError
from .scanners import Finding, extract_prompt_text, scan_text
from .settings import Settings
from .store import AuditStore

settings = Settings()
policy = PolicyEngine(settings.policy_path)
store = AuditStore(sqlite_path=settings.sqlite_path, database_url=settings.database_url, tenant_id=settings.org_id)
audit = AuditPipeline(
    store,
    enabled=settings.audit_async_enabled,
    max_size=settings.audit_queue_max_size,
    spool_dir=settings.endpoint_event_spool_dir,
)
budget = BudgetService(store=store, redis_url=settings.redis_url, tenant_id=settings.org_id)
devices = DeviceTrustService(
    store, enrollment_token=settings.device_enrollment_token, trust_mode=settings.device_trust_mode
)
identity = IdentityService(settings, device_service=devices)
providers = MultiProviderClient(settings)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    await audit.start()
    yield
    await audit.stop()


app = FastAPI(title="AISecurityControlPlane", version="0.5.0", lifespan=lifespan)

# MVP convenience for local browser extension calls. Lock this down in production.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


SENSITIVE_UPLOAD_EXTENSIONS = {
    ".pem",
    ".key",
    ".p12",
    ".pfx",
    ".env",
    ".kubeconfig",
    ".tfstate",
    ".sqlite",
    ".db",
}

SENSITIVE_UPLOAD_NAMES = {
    "id_rsa",
    "id_ed25519",
    "credentials",
    "credentials.csv",
    "aws_credentials",
    "secrets.yaml",
    "secrets.yml",
    "terraform.tfstate",
}


def estimate_cost(model: str, input_tokens: int, output_tokens: int) -> float:
    p = policy.pricing_for_model(model)
    return (input_tokens / 1_000_000) * float(p.get("input", 0.0)) + (output_tokens / 1_000_000) * float(
        p.get("output", 0.0)
    )


def estimate_reservation(model: str, prompt_text: str, max_tokens: int | None) -> float:
    # Cheap, local approximation. Real production version should use provider token counting.
    approx_input_tokens = max(1, int(len(prompt_text or "") / 4))
    approx_output_tokens = int(max_tokens or policy.policy.get("defaults", {}).get("max_output_tokens", 4096))
    estimated = estimate_cost(model, approx_input_tokens, approx_output_tokens)
    return max(float(settings.budget_default_reservation_usd), estimated)


def month_start_iso() -> str:
    now = datetime.now(timezone.utc)
    return now.replace(day=1, hour=0, minute=0, second=0, microsecond=0).isoformat()


def day_start_iso() -> str:
    now = datetime.now(timezone.utc)
    return now.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()


def prompt_hash(prompt_text: str) -> str:
    return hashlib.sha256(prompt_text.encode("utf-8")).hexdigest()


def filename_findings(file_names: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for raw_name in file_names or []:
        name = str(raw_name or "").strip()
        lower = name.lower()
        if not lower:
            continue
        if any(lower.endswith(ext) for ext in SENSITIVE_UPLOAD_EXTENSIONS) or lower in SENSITIVE_UPLOAD_NAMES:
            findings.append(
                Finding(
                    "sensitive_file_upload",
                    "high",
                    f"Sensitive-looking file upload name detected: {name}",
                )
            )
    return findings


def build_web_text(body: dict[str, Any]) -> str:
    pieces: list[str] = []
    for key in ("text", "body", "prompt", "selected_text", "input_value"):
        value = body.get(key)
        if isinstance(value, str):
            pieces.append(value)
    request_body = body.get("request_body")
    if isinstance(request_body, str):
        pieces.append(request_body)
    return "\n".join(pieces)


def log_audit_event(**kwargs: Any) -> None:
    kwargs.setdefault("tenant_id", settings.org_id)
    kwargs.setdefault("policy_version", policy.policy_version)
    audit.log_event(**kwargs)


async def request_identity(
    request: Request,
    *,
    header_user: str = "anonymous",
    header_groups: str = "",
    header_device_id: str = "unknown-device",
):
    return await identity.resolve(
        request,
        header_user=header_user,
        header_groups=header_groups,
        header_device_id=header_device_id,
    )


@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "AISecurityControlPlane",
        "version": "0.5.0",
        "tenant_id": settings.org_id,
        "policy_version": policy.policy_version,
        "audit_pipeline": audit.metrics(),
        "budget_mode": budget.mode,
        "database_url_configured": bool(settings.database_url),
        "redis_url_configured": bool(settings.redis_url),
        "auth_mode": settings.auth_mode,
        "device_trust_mode": settings.device_trust_mode,
        "oidc_configured": bool(settings.oidc_issuer),
        "jumpcloud_enrichment": bool(settings.jumpcloud_enable_enrichment and settings.jumpcloud_api_key),
        "providers_configured": providers.configured_providers(),
        "providers_supported": list(policy.supported_providers().keys()),
    }


@app.post("/v1/control/device/enroll")
async def enroll_device(request: Request, x_secureai_enrollment_token: str = Header(default="")):
    body = await request.json()
    user = str(body.get("user") or body.get("email") or "").strip()
    if not user:
        raise HTTPException(status_code=400, detail="user or email is required")
    try:
        result = devices.enroll(
            provided_enrollment_token=x_secureai_enrollment_token,
            user=user,
            device_name=body.get("device_name"),
            platform=body.get("platform"),
            serial_number=body.get("serial_number"),
            mdm_provider=body.get("mdm_provider"),
            mdm_device_id=body.get("mdm_device_id"),
            public_key_pem=body.get("public_key_pem"),
            posture=body.get("posture") if isinstance(body.get("posture"), dict) else {},
        )
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    log_audit_event(
        user=user,
        app="control-plane",
        device_id=result["device_id"],
        event_type="device_enroll",
        requested_model=None,
        model_used=None,
        decision="trusted",
        reasons=["Device enrolled"],
        findings=[],
        extra={k: v for k, v in result.items() if k != "device_token"},
    )
    return result


@app.get("/v1/control/identity/me")
async def identity_me(
    request: Request,
    x_secureai_user: str = Header(default="anonymous"),
    x_secureai_groups: str = Header(default=""),
    x_secureai_device: str = Header(default="unknown-device"),
):
    ctx = await request_identity(
        request, header_user=x_secureai_user, header_groups=x_secureai_groups, header_device_id=x_secureai_device
    )
    return {
        "authenticated": ctx.authenticated,
        "provider": ctx.provider,
        "user": ctx.user,
        "email": ctx.email,
        "subject": ctx.subject,
        "groups": ctx.groups,
        "device_trusted": ctx.device_trusted,
        "device_id": ctx.device_id,
        "device_reason": ctx.device_reason,
        "device_posture": ctx.device_posture,
        "jumpcloud": ctx.jumpcloud,
        "auth_mode": settings.auth_mode,
        "device_trust_mode": settings.device_trust_mode,
    }


@app.get("/v1/control/devices")
async def list_devices(
    request: Request,
    user: str | None = None,
    limit: int = 100,
    x_secureai_user: str = Header(default="anonymous"),
    x_secureai_groups: str = Header(default=""),
    x_secureai_device: str = Header(default="unknown-device"),
):
    ctx = await request_identity(
        request, header_user=x_secureai_user, header_groups=x_secureai_groups, header_device_id=x_secureai_device
    )
    target_user = user or (ctx.user if ctx.authenticated else None)
    return {"devices": store.list_devices(user=target_user, limit=limit, tenant_id=settings.org_id)}


@app.get("/v1/extension/config")
def extension_config():
    return {
        "service": "AISecurityControlPlane",
        "version": "0.5.0",
        "tenant_id": settings.org_id,
        "policy_version": policy.policy_version,
        "web_controls": policy.web_controls(),
        "web_model_control": policy.web_model_control(),
        "sensitive_upload_extensions": sorted(SENSITIVE_UPLOAD_EXTENSIONS),
        "sensitive_upload_names": sorted(SENSITIVE_UPLOAD_NAMES),
    }


@app.post("/v1/policy/evaluate")
async def evaluate_policy(request: Request):
    body = await request.json()
    text = body.get("text") or extract_prompt_text(body)
    findings = scan_text(text)
    fake_payload = {"messages": [{"role": "user", "content": text}], "model": body.get("model", "auto-secure")}
    decision = policy.decide(fake_payload, findings)
    return {
        "decision": decision.decision,
        "reasons": decision.reasons,
        "findings": [f.to_dict() for f in findings],
        "requested_model": decision.requested_model,
        "model_used": decision.model_used,
        "policy_version": policy.policy_version,
    }


@app.get("/v1/control/policy/bundle")
async def policy_bundle(
    request: Request,
    x_secureai_user: str = Header(default="anonymous"),
    x_secureai_device: str = Header(default="unknown-device"),
    x_secureai_groups: str = Header(default=""),
):
    ctx = await request_identity(
        request, header_user=x_secureai_user, header_groups=x_secureai_groups, header_device_id=x_secureai_device
    )
    return policy.policy_bundle(
        user=ctx.user,
        device_id=ctx.device_id or x_secureai_device,
        groups=ctx.groups,
        tenant_id=settings.org_id,
        signing_secret=settings.secureai_signing_secret,
        authenticated=ctx.authenticated,
        provider=ctx.provider,
        device_trusted=ctx.device_trusted,
        device_posture=ctx.device_posture,
        jumpcloud=ctx.jumpcloud,
    )


@app.post("/v1/control/policy/reload")
def reload_policy():
    policy.reload()
    return {"status": "reloaded", "policy_version": policy.policy_version, "policy_hash": policy.policy_hash()}


@app.post("/v1/control/events/ingest")
async def ingest_events(request: Request):
    body = await request.json()
    events = body.get("events", body if isinstance(body, list) else [])
    if not isinstance(events, list):
        raise HTTPException(status_code=400, detail="Expected {'events': [...]} or a JSON array")
    accepted = 0
    for event in events[:1000]:
        if not isinstance(event, dict):
            continue
        log_audit_event(
            user=str(event.get("user") or event.get("user_id") or "unknown"),
            app=str(event.get("app") or event.get("source") or "endpoint"),
            device_id=event.get("device_id"),
            event_type=event.get("event_type") or event.get("type"),
            requested_model=event.get("requested_model"),
            model_used=event.get("model_used"),
            decision=str(event.get("decision") or "audit"),
            reasons=event.get("reasons") if isinstance(event.get("reasons"), list) else [],
            findings=event.get("findings") if isinstance(event.get("findings"), list) else [],
            input_tokens=int(event.get("input_tokens") or 0),
            output_tokens=int(event.get("output_tokens") or 0),
            estimated_cost_usd=float(event.get("estimated_cost_usd") or 0.0),
            raw_prompt_hash=event.get("raw_prompt_hash"),
            extra={k: v for k, v in event.items() if k not in {"raw_prompt", "prompt", "response"}},
        )
        accepted += 1
    return {"accepted": accepted, "max_batch_size": 1000, "audit_pipeline": audit.metrics()}


@app.post("/v1/web/evaluate")
async def evaluate_web_event(
    request: Request,
    x_secureai_user: str = Header(default="browser-user"),
    x_secureai_app: str = Header(default="claude.ai"),
    x_secureai_device: str = Header(default="browser-device"),
    x_secureai_groups: str = Header(default=""),
):
    """Policy endpoint for browser/TLS interception events."""
    ctx = await request_identity(
        request, header_user=x_secureai_user, header_groups=x_secureai_groups, header_device_id=x_secureai_device
    )
    body: dict[str, Any] = await request.json()
    event_type = str(body.get("event_type") or body.get("source") or "web_event")
    url = str(body.get("url") or "")
    method = str(body.get("method") or "").upper()
    file_names = body.get("file_names") or []
    if not isinstance(file_names, list):
        file_names = [str(file_names)]

    text = build_web_text(body)
    findings = scan_text(text) + filename_findings(file_names)
    findings_json = [f.to_dict() for f in findings]

    fake_payload = {
        "model": body.get("model", "auto-secure"),
        "messages": [{"role": "user", "content": text}],
        "request_body": body.get("request_body"),
        "web_event": {
            "event_type": event_type,
            "url": url,
            "method": method,
            "file_names": file_names,
            "request_body": body.get("request_body"),
        },
    }
    decision = policy.decide_web(fake_payload, findings)
    raw_hash = prompt_hash(text) if text else None

    reasons = list(decision.reasons)
    if url:
        reasons.append(f"web_url={url[:300]}")
    if method:
        reasons.append(f"method={method}")
    if event_type:
        reasons.append(f"event_type={event_type}")
    if file_names:
        reasons.append("file_names=" + ",".join(str(name)[:120] for name in file_names[:10]))

    log_audit_event(
        user=ctx.user,
        app=x_secureai_app,
        device_id=ctx.device_id or x_secureai_device,
        event_type=event_type,
        requested_model=decision.requested_model,
        model_used=decision.model_used,
        decision=decision.decision,
        reasons=reasons,
        findings=findings_json,
        raw_prompt_hash=raw_hash,
        extra={
            "url": url[:500],
            "method": method,
            "rewrite_applied_fields": decision.rewrite_applied_fields or [],
            "identity_provider": ctx.provider,
            "authenticated": ctx.authenticated,
            "device_trusted": ctx.device_trusted,
            "device_reason": ctx.device_reason,
            "jumpcloud": ctx.jumpcloud,
        },
    )

    return {
        "decision": decision.decision,
        "reasons": decision.reasons,
        "findings": findings_json,
        "requested_model": decision.requested_model,
        "model_used": decision.model_used,
        "event_type": event_type,
        "policy_version": policy.policy_version,
        "rewrite_request_body": decision.rewrite_request_body,
        "rewrite_applied_fields": decision.rewrite_applied_fields or [],
        "identity": {
            "user": ctx.user,
            "provider": ctx.provider,
            "authenticated": ctx.authenticated,
            "device_trusted": ctx.device_trusted,
            "device_id": ctx.device_id,
        },
    }



@app.get("/v1/providers")
def list_providers():
    configured = set(providers.configured_providers())
    provider_config = policy.supported_providers()
    return {
        "providers": [
            {
                "name": name,
                "configured": name in configured,
                "models": config.get("models", []) if isinstance(config, dict) else [],
                "default_model": config.get("default_model") if isinstance(config, dict) else None,
                "notes": config.get("notes") if isinstance(config, dict) else None,
            }
            for name, config in provider_config.items()
        ],
        "model_aliases": policy.policy.get("model_aliases", {}),
        "default_provider": policy.policy.get("defaults", {}).get("default_provider", "anthropic"),
        "fallback": policy.fallback_config(),
        "policy_version": policy.policy_version,
    }


@app.get("/v1/providers/health")
def provider_health():
    configured = set(providers.configured_providers())
    return {
        "policy_version": policy.policy_version,
        "providers": [
            {
                "name": name,
                "configured": name in configured,
                "status": "configured" if name in configured else "not_configured",
                "default_model": config.get("default_model") if isinstance(config, dict) else None,
            }
            for name, config in policy.supported_providers().items()
        ],
        "fallback": policy.fallback_config(),
    }


@app.post("/v1/chat/completions")
async def proxy_chat_completions(
    request: Request,
    x_secureai_user: str = Header(default="anonymous"),
    x_secureai_app: str = Header(default="unknown"),
    x_secureai_device: str = Header(default="unknown-device"),
    x_secureai_groups: str = Header(default=""),
):
    """OpenAI-compatible gateway route that can route to Anthropic, OpenAI, or Gemini.

    This is the preferred multi-provider API surface for tools that can set a custom base_url.
    """
    ctx = await request_identity(
        request, header_user=x_secureai_user, header_groups=x_secureai_groups, header_device_id=x_secureai_device
    )
    payload: dict[str, Any] = await request.json()
    prompt_text = extract_prompt_text(payload)
    findings = scan_text(prompt_text)
    decision = policy.decide(payload, findings)
    findings_json = [f.to_dict() for f in findings]
    raw_hash = prompt_hash(prompt_text)
    provider_name = policy.provider_for_model(decision.model_used)

    if decision.decision == "block":
        log_audit_event(
            user=ctx.user,
            app=x_secureai_app,
            device_id=ctx.device_id or x_secureai_device,
            event_type="api_chat_completions",
            requested_model=decision.requested_model,
            model_used=decision.model_used,
            decision="block",
            reasons=decision.reasons,
            findings=findings_json,
            raw_prompt_hash=raw_hash,
            extra={"provider": provider_name},
        )
        return JSONResponse(
            status_code=403,
            content={"error": {"type": "secureai_policy_block", "message": "Request blocked by AISecurityControlPlane policy", "reasons": decision.reasons, "findings": findings_json}},
        )

    outbound = dict(payload)
    outbound["model"] = decision.model_used
    outbound["max_tokens"] = policy.cap_chat_tokens(outbound)

    # Budget-aware model downgrade before reservation. This prevents users near budget
    # limits from consuming premium models when policy defines a lower-cost substitute.
    if settings.budget_reservation_enabled:
        initial_reserve = estimate_reservation(decision.model_used or "", prompt_text, outbound.get("max_tokens"))
        snapshot = budget.spend_snapshot(ctx.user, day_start_iso(), month_start_iso())
        projected_month = float(snapshot.get("monthly_actual_usd") or 0.0) + float(snapshot.get("monthly_reserved_usd") or 0.0) + initial_reserve
        downgrade_model = policy.budget_downgrade_model(decision.model_used, projected_month, policy.monthly_budget())
        if downgrade_model and downgrade_model != decision.model_used:
            decision.reasons.append(f"Budget-aware downgrade from {decision.model_used} to {downgrade_model}")
            decision.model_used = downgrade_model
            provider_name = policy.provider_for_model(decision.model_used)
            outbound["model"] = decision.model_used
            outbound["max_tokens"] = policy.cap_chat_tokens(outbound)

    reserved_usd = 0.0
    reservation = {"allowed": True, "reserved_usd": 0.0}
    if settings.budget_reservation_enabled:
        reserve_amount = estimate_reservation(decision.model_used or "", prompt_text, outbound.get("max_tokens"))
        reservation = budget.reserve(ctx.user, reserve_amount, daily_budget=policy.daily_budget(), monthly_budget=policy.monthly_budget(), day_start_iso=day_start_iso(), month_start_iso=month_start_iso())
        reserved_usd = float(reservation.get("reserved_usd") or 0.0)
        if not reservation.get("allowed"):
            reasons = ["User budget would be exceeded"]
            log_audit_event(user=ctx.user, app=x_secureai_app, device_id=ctx.device_id or x_secureai_device, event_type="api_chat_completions", requested_model=decision.requested_model, model_used=decision.model_used, decision="block", reasons=reasons, findings=findings_json, raw_prompt_hash=raw_hash, extra={"budget": reservation, "provider": provider_name})
            return JSONResponse(status_code=402, content={"error": {"type": "secureai_budget_block", "message": "User budget would be exceeded", "budget": reservation}})

    attempts: list[dict[str, Any]] = []
    provider_result = None
    final_provider = provider_name
    final_model = decision.model_used or ""
    fallback_candidates = policy.fallback_candidates(decision.model_used)

    for candidate in fallback_candidates:
        candidate_provider = candidate["provider"]
        candidate_model = candidate["model"]
        if not providers.configured(candidate_provider):
            attempts.append({"provider": candidate_provider, "model": candidate_model, "status": "skipped_not_configured"})
            continue

        attempt_payload = dict(outbound)
        attempt_payload["model"] = candidate_model
        try:
            candidate_result = await providers.chat_completions(provider=candidate_provider, model=candidate_model, payload=attempt_payload)
        except ProviderError as e:
            attempts.append({"provider": candidate_provider, "model": candidate_model, "status": "provider_error", "error": str(e)})
            continue
        except Exception as e:
            attempts.append({"provider": candidate_provider, "model": candidate_model, "status": "exception", "error": type(e).__name__})
            continue

        attempts.append({"provider": candidate_provider, "model": candidate_model, "status_code": candidate_result.status_code})
        provider_result = candidate_result
        final_provider = candidate_provider
        final_model = candidate_model
        if not policy.should_fallback_status(candidate_result.status_code):
            break

    if provider_result is None:
        budget.reconcile(ctx.user, reserved_usd, 0.0)
        log_audit_event(
            user=ctx.user,
            app=x_secureai_app,
            device_id=ctx.device_id or x_secureai_device,
            event_type="api_chat_completions",
            requested_model=decision.requested_model,
            model_used=decision.model_used,
            decision="provider_error",
            reasons=["No configured or healthy provider could satisfy the request"],
            findings=findings_json,
            raw_prompt_hash=raw_hash,
            extra={"attempts": attempts},
        )
        return JSONResponse(status_code=502, content={"error": {"type": "secureai_provider_unavailable", "message": "No configured or healthy provider could satisfy the request", "attempts": attempts}})

    estimated = estimate_cost(final_model, provider_result.input_tokens, provider_result.output_tokens)
    budget.reconcile(ctx.user, reserved_usd, estimated)

    fallback_used = final_model != decision.model_used or final_provider != provider_name
    audit_decision = "fallback" if fallback_used else decision.decision
    audit_reasons = list(decision.reasons)
    if fallback_used:
        audit_reasons.append(f"Provider fallback selected {final_provider}/{final_model}")

    log_audit_event(
        user=ctx.user,
        app=x_secureai_app,
        device_id=ctx.device_id or x_secureai_device,
        event_type="api_chat_completions",
        requested_model=decision.requested_model,
        model_used=final_model,
        decision=audit_decision,
        reasons=audit_reasons,
        findings=findings_json,
        input_tokens=provider_result.input_tokens,
        output_tokens=provider_result.output_tokens,
        estimated_cost_usd=estimated,
        raw_prompt_hash=raw_hash,
        extra={"provider": final_provider, "provider_request_id": provider_result.request_id, "reservation": reservation, "attempts": attempts, "fallback_used": fallback_used},
    )

    result = provider_result.body
    if isinstance(result, dict):
        result.setdefault("secureai", {})
        result["secureai"].update({
            "decision": audit_decision,
            "requested_model": decision.requested_model,
            "model_used": final_model,
            "provider": final_provider,
            "fallback_used": fallback_used,
            "attempts": attempts,
            "findings": findings_json,
            "estimated_cost_usd": round(estimated, 8),
            "policy_version": policy.policy_version,
            "identity": {"user": ctx.user, "provider": ctx.provider, "authenticated": ctx.authenticated, "device_trusted": ctx.device_trusted, "device_id": ctx.device_id},
        })
    return JSONResponse(status_code=provider_result.status_code, content=result)




ADMIN_HTML = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>AISecurityControlPlane Admin</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 0; background: #0f172a; color: #e5e7eb; }
    header { padding: 24px 32px; background: #111827; border-bottom: 1px solid #334155; }
    main { padding: 24px 32px; display: grid; gap: 20px; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; }
    .card { background: #111827; border: 1px solid #334155; border-radius: 14px; padding: 18px; box-shadow: 0 8px 24px rgba(0,0,0,.2); }
    .metric { font-size: 32px; font-weight: 700; margin-top: 8px; }
    table { width: 100%; border-collapse: collapse; font-size: 14px; }
    th, td { border-bottom: 1px solid #334155; padding: 10px; text-align: left; vertical-align: top; }
    th { color: #93c5fd; font-weight: 600; }
    textarea { width: 100%; min-height: 260px; background: #020617; color: #e5e7eb; border: 1px solid #334155; border-radius: 10px; padding: 12px; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
    button { background: #2563eb; color: white; border: 0; border-radius: 10px; padding: 10px 14px; cursor: pointer; }
    button.secondary { background: #475569; }
    .muted { color: #94a3b8; }
    .warn { color: #fbbf24; }
    pre { overflow: auto; background: #020617; padding: 12px; border-radius: 10px; border: 1px solid #334155; }
  </style>
</head>
<body>
<header>
  <h1>AISecurityControlPlane Admin</h1>
  <div class="muted">Local/public-preview console for usage, policy, models, devices, and audit.</div>
</header>
<main>
  <section class="grid" id="metrics"></section>
  <section class="card"><h2>Provider Models</h2><div id="models"></div></section>
  <section class="card"><h2>Recent Audit</h2><div id="audit"></div></section>
  <section class="card"><h2>Devices</h2><div id="devices"></div></section>
  <section class="card"><h2>Policy Simulator</h2><textarea id="simText">{"model":"auto-secure","messages":[{"role":"user","content":"Summarize this for security leadership."}]}</textarea><br><br><button onclick="simulate()">Simulate</button><pre id="simResult"></pre></section>
  <section class="card"><h2>Policy</h2><p class="warn">Policy write is intended for local/dev use. Disable ADMIN_ENABLE_POLICY_WRITE in production.</p><button class="secondary" onclick="loadPolicy()">Reload Policy</button> <button onclick="validatePolicy()">Validate</button> <button onclick="savePolicy()">Save</button><br><br><textarea id="policy"></textarea><pre id="policyResult"></pre></section>
</main>
<script>
async function getJson(url, opts={}) { const r = await fetch(url, opts); const t = await r.text(); try { return JSON.parse(t); } catch { return {status:r.status, body:t}; } }
function table(rows) { if (!rows || !rows.length) return '<p class="muted">No data yet.</p>'; const cols = Object.keys(rows[0]); return '<table><thead><tr>'+cols.map(c=>`<th>${c}</th>`).join('')+'</tr></thead><tbody>'+rows.map(r=>'<tr>'+cols.map(c=>`<td>${typeof r[c]==='object'?JSON.stringify(r[c]):(r[c]??'')}</td>`).join('')+'</tr>').join('')+'</tbody></table>'; }
async function load() {
  const overview = await getJson('/v1/admin/overview');
  document.getElementById('metrics').innerHTML = [
    ['Events', overview.events], ['Spend', '$'+Number(overview.spend_usd||0).toFixed(4)], ['Active Users', overview.active_users], ['Devices', overview.devices], ['Policy', overview.policy_version]
  ].map(([k,v])=>`<div class="card"><div class="muted">${k}</div><div class="metric">${v}</div></div>`).join('');
  document.getElementById('models').innerHTML = table((await getJson('/v1/admin/models')).models || []);
  document.getElementById('audit').innerHTML = table((await getJson('/v1/admin/audit?limit=20')).events || []);
  document.getElementById('devices').innerHTML = table((await getJson('/v1/admin/devices')).devices || []);
  await loadPolicy();
}
async function loadPolicy(){ const p=await getJson('/v1/admin/policy'); document.getElementById('policy').value = p.policy_yaml || ''; }
async function validatePolicy(){ const body = JSON.stringify({policy_yaml: document.getElementById('policy').value}); const r=await getJson('/v1/admin/policy/validate',{method:'POST',headers:{'content-type':'application/json'},body}); document.getElementById('policyResult').textContent=JSON.stringify(r,null,2); }
async function savePolicy(){ const body = JSON.stringify({policy_yaml: document.getElementById('policy').value}); const r=await getJson('/v1/admin/policy',{method:'PUT',headers:{'content-type':'application/json'},body}); document.getElementById('policyResult').textContent=JSON.stringify(r,null,2); }
async function simulate(){ let body; try { body=JSON.parse(document.getElementById('simText').value); } catch(e) { body={text:document.getElementById('simText').value}; } const r=await getJson('/v1/admin/simulate',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)}); document.getElementById('simResult').textContent=JSON.stringify(r,null,2); }
load();
</script>
</body>
</html>
"""


def _admin_groups() -> set[str]:
    return {g.strip() for g in (settings.admin_groups or "").split(",") if g.strip()}


async def require_admin(request: Request) -> Any:
    ctx = await request_identity(
        request,
        header_user=request.headers.get("x-secureai-user", "admin-dev"),
        header_groups=request.headers.get("x-secureai-groups", "security"),
        header_device_id=request.headers.get("x-secureai-device", "admin-device"),
    )
    if settings.admin_auth_mode == "required" and not ctx.authenticated:
        raise HTTPException(status_code=401, detail="Admin OIDC authentication required")
    required_groups = _admin_groups()
    if settings.admin_auth_mode == "required" and required_groups and not required_groups.intersection(set(ctx.groups)):
        raise HTTPException(status_code=403, detail="Admin group membership required")
    if settings.admin_require_trusted_device and not ctx.device_trusted:
        raise HTTPException(status_code=403, detail="Trusted admin device required")
    return ctx


@app.get("/admin", response_class=HTMLResponse)
async def admin_console(request: Request):
    await require_admin(request)
    return HTMLResponse(ADMIN_HTML)


@app.get("/v1/admin/overview")
async def admin_overview(request: Request):
    await require_admin(request)
    data = store.overview(day_start_iso(), tenant_id=settings.org_id)
    data.update({
        "tenant_id": settings.org_id,
        "policy_version": policy.policy_version,
        "audit_pipeline": audit.metrics(),
        "budget_mode": budget.mode,
        "providers_configured": providers.configured_providers(),
    })
    return data


@app.get("/v1/admin/audit")
async def admin_audit(request: Request, limit: int = 100):
    await require_admin(request)
    return {"events": store.recent_events(limit=limit, tenant_id=settings.org_id)}


@app.get("/v1/admin/users")
async def admin_users(request: Request, limit: int = 100):
    await require_admin(request)
    return {"users": store.users_summary(limit=limit, tenant_id=settings.org_id)}


@app.get("/v1/admin/models")
async def admin_models(request: Request):
    await require_admin(request)
    model_usage = {row["model"]: row for row in store.model_usage(limit=500, tenant_id=settings.org_id)}
    configured = set(providers.configured_providers())
    rows = []
    for provider_name, config in policy.supported_providers().items():
        for model_name in (config.get("models", []) if isinstance(config, dict) else []):
            usage = model_usage.get(model_name, {})
            rows.append({
                "provider": provider_name,
                "model": model_name,
                "configured": provider_name in configured,
                "events": usage.get("events", 0),
                "spend_usd": usage.get("spend_usd", 0.0),
            })
    return {"models": rows, "aliases": policy.policy.get("model_aliases", {})}


@app.get("/v1/admin/devices")
async def admin_devices(request: Request, limit: int = 250):
    await require_admin(request)
    return {"devices": store.list_devices(limit=limit, tenant_id=settings.org_id)}


@app.post("/v1/admin/devices/{device_id}/status")
async def admin_device_status(device_id: str, request: Request):
    ctx = await require_admin(request)
    body = await request.json()
    status = str(body.get("status") or "").strip().lower()
    if status not in {"trusted", "revoked", "quarantined"}:
        raise HTTPException(status_code=400, detail="status must be trusted, revoked, or quarantined")
    updated = store.update_device_status(device_id, status, tenant_id=settings.org_id)
    if not updated:
        raise HTTPException(status_code=404, detail="device not found")
    log_audit_event(user=ctx.user, app="admin", device_id=ctx.device_id, event_type="admin_device_status", requested_model=None, model_used=None, decision="updated", reasons=[f"Device {device_id} set to {status}"], findings=[], extra={"device_id": device_id, "status": status})
    return {"updated": True, "device_id": device_id, "status": status}


@app.get("/v1/admin/policy")
async def admin_policy(request: Request):
    await require_admin(request)
    return {"policy_version": policy.policy_version, "policy_hash": policy.policy_hash(), "policy": policy.policy, "policy_yaml": policy.path.read_text(encoding="utf-8")}


@app.post("/v1/admin/policy/validate")
async def admin_policy_validate(request: Request):
    await require_admin(request)
    body = await request.json()
    text = str(body.get("policy_yaml") or "")
    try:
        parsed = yaml.safe_load(text) or {}
    except Exception as exc:
        return {"valid": False, "error": f"YAML parse error: {exc}"}
    required = ["defaults", "providers", "model_aliases", "security"]
    missing = [k for k in required if k not in parsed]
    return {"valid": not missing, "missing": missing, "version": parsed.get("version")}


@app.put("/v1/admin/policy")
async def admin_policy_update(request: Request):
    ctx = await require_admin(request)
    if not settings.admin_enable_policy_write:
        raise HTTPException(status_code=403, detail="Policy write is disabled")
    body = await request.json()
    text = str(body.get("policy_yaml") or "")
    try:
        parsed = yaml.safe_load(text) or {}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"YAML parse error: {exc}") from exc
    if not isinstance(parsed, dict) or "defaults" not in parsed:
        raise HTTPException(status_code=400, detail="Policy must be a YAML mapping and include defaults")
    backup = policy.path.with_suffix(policy.path.suffix + f".{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}.bak")
    backup.write_text(policy.path.read_text(encoding="utf-8"), encoding="utf-8")
    policy.path.write_text(text, encoding="utf-8")
    policy.reload()
    log_audit_event(user=ctx.user, app="admin", device_id=ctx.device_id, event_type="admin_policy_update", requested_model=None, model_used=None, decision="updated", reasons=["Policy updated through admin API"], findings=[], extra={"backup": str(backup), "policy_version": policy.policy_version})
    return {"updated": True, "policy_version": policy.policy_version, "backup": str(backup)}


@app.post("/v1/admin/simulate")
async def admin_simulate(request: Request):
    await require_admin(request)
    payload: dict[str, Any] = await request.json()
    prompt_text = extract_prompt_text(payload) or build_web_text(payload)
    findings = scan_text(prompt_text)
    decision = policy.decide_web(payload, findings) if payload.get("web_event") or payload.get("request_body") else policy.decide(payload, findings)
    model = decision.model_used or decision.requested_model
    return {
        "decision": decision.decision,
        "requested_model": decision.requested_model,
        "model_used": decision.model_used,
        "provider": policy.provider_for_model(model),
        "reasons": decision.reasons,
        "findings": [f.to_dict() for f in findings],
        "rewrite_request_body": decision.rewrite_request_body,
        "rewrite_applied_fields": decision.rewrite_applied_fields or [],
        "policy_version": policy.policy_version,
    }


@app.get("/v1/audit/recent")
def recent_audit(limit: int = 50):
    return {"events": store.recent_events(limit=limit, tenant_id=settings.org_id)}


@app.get("/v1/control/metrics")
def metrics():
    return {
        "policy_version": policy.policy_version,
        "audit_pipeline": audit.metrics(),
        "budget_mode": budget.mode,
        "decision_counts_today": store.decision_counts_since(day_start_iso(), tenant_id=settings.org_id),
    }


@app.get("/v1/spend")
def spend(x_secureai_user: str = Header(default="anonymous")):
    snapshot = budget.spend_snapshot(x_secureai_user, day_start_iso(), month_start_iso())
    return {
        "user": x_secureai_user,
        "daily_spend_usd": round(snapshot["daily_actual_usd"], 6),
        "daily_reserved_usd": round(snapshot["daily_reserved_usd"], 6),
        "monthly_spend_usd": round(snapshot["monthly_actual_usd"], 6),
        "monthly_reserved_usd": round(snapshot["monthly_reserved_usd"], 6),
        "daily_budget_usd": policy.daily_budget(),
        "monthly_budget_usd": policy.monthly_budget(),
        "budget_mode": snapshot["mode"],
    }


@app.post("/v1/messages")
async def proxy_claude_messages(
    request: Request,
    x_secureai_user: str = Header(default="anonymous"),
    x_secureai_app: str = Header(default="unknown"),
    x_secureai_device: str = Header(default="unknown-device"),
    x_secureai_groups: str = Header(default=""),
):
    ctx = await request_identity(
        request, header_user=x_secureai_user, header_groups=x_secureai_groups, header_device_id=x_secureai_device
    )
    if not settings.anthropic_api_key:
        raise HTTPException(status_code=500, detail="ANTHROPIC_API_KEY is not configured")

    payload: dict[str, Any] = await request.json()
    prompt_text = extract_prompt_text(payload)
    findings = scan_text(prompt_text)
    decision = policy.decide(payload, findings)
    findings_json = [f.to_dict() for f in findings]
    raw_hash = prompt_hash(prompt_text)

    if decision.decision == "block":
        log_audit_event(
            user=ctx.user,
            app=x_secureai_app,
            device_id=ctx.device_id or x_secureai_device,
            event_type="api_messages",
            requested_model=decision.requested_model,
            model_used=decision.model_used,
            decision="block",
            reasons=decision.reasons,
            findings=findings_json,
            raw_prompt_hash=raw_hash,
        )
        return JSONResponse(
            status_code=403,
            content={
                "error": {
                    "type": "secureai_policy_block",
                    "message": "Request blocked by AISecurityControlPlane policy",
                    "reasons": decision.reasons,
                    "findings": findings_json,
                }
            },
        )

    outbound = dict(payload)
    outbound["model"] = decision.model_used
    outbound["max_tokens"] = policy.cap_max_tokens(outbound)

    reserved_usd = 0.0
    reservation = {"allowed": True, "reserved_usd": 0.0}
    if settings.budget_reservation_enabled:
        reserve_amount = estimate_reservation(decision.model_used or "", prompt_text, outbound.get("max_tokens"))
        reservation = budget.reserve(
            ctx.user,
            reserve_amount,
            daily_budget=policy.daily_budget(),
            monthly_budget=policy.monthly_budget(),
            day_start_iso=day_start_iso(),
            month_start_iso=month_start_iso(),
        )
        reserved_usd = float(reservation.get("reserved_usd") or 0.0)
        if not reservation.get("allowed"):
            reasons = ["User budget would be exceeded"]
            log_audit_event(
                user=ctx.user,
                app=x_secureai_app,
                device_id=ctx.device_id or x_secureai_device,
                event_type="api_messages",
                requested_model=decision.requested_model,
                model_used=decision.model_used,
                decision="block",
                reasons=reasons,
                findings=findings_json,
                raw_prompt_hash=raw_hash,
                extra={"budget": reservation},
            )
            return JSONResponse(
                status_code=402,
                content={
                    "error": {
                        "type": "secureai_budget_block",
                        "message": "User budget would be exceeded",
                        "budget": reservation,
                    }
                },
            )

    url = f"{settings.anthropic_base_url.rstrip('/')}/v1/messages"
    headers = {
        "x-api-key": settings.anthropic_api_key,
        "anthropic-version": settings.anthropic_version,
        "content-type": "application/json",
    }

    upstream = None
    try:
        async with httpx.AsyncClient(timeout=120.0) as client:
            upstream = await client.post(url, json=outbound, headers=headers)
    except Exception as e:
        budget.reconcile(ctx.user, reserved_usd, 0.0)
        log_audit_event(
            user=ctx.user,
            app=x_secureai_app,
            device_id=ctx.device_id or x_secureai_device,
            event_type="api_messages",
            requested_model=decision.requested_model,
            model_used=decision.model_used,
            decision="provider_error",
            reasons=[f"Anthropic provider request failed: {type(e).__name__}"],
            findings=findings_json,
            raw_prompt_hash=raw_hash,
        )
        raise

    anthropic_request_id = upstream.headers.get("request-id") or upstream.headers.get("anthropic-request-id")

    try:
        result = upstream.json()
    except Exception:
        result = {"raw": upstream.text}

    input_tokens = 0
    output_tokens = 0
    if isinstance(result, dict):
        usage = result.get("usage") or {}
        input_tokens = int(usage.get("input_tokens") or 0)
        output_tokens = int(usage.get("output_tokens") or 0)

    estimated = estimate_cost(decision.model_used or "", input_tokens, output_tokens)
    budget.reconcile(ctx.user, reserved_usd, estimated)

    log_audit_event(
        user=ctx.user,
        app=x_secureai_app,
        device_id=ctx.device_id or x_secureai_device,
        event_type="api_messages",
        requested_model=decision.requested_model,
        model_used=decision.model_used,
        decision=decision.decision,
        reasons=decision.reasons,
        findings=findings_json,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        estimated_cost_usd=estimated,
        anthropic_request_id=anthropic_request_id,
        raw_prompt_hash=raw_hash,
        extra={"reservation": reservation},
    )

    if isinstance(result, dict):
        result.setdefault("secureai", {})
        result["secureai"].update(
            {
                "decision": decision.decision,
                "requested_model": decision.requested_model,
                "model_used": decision.model_used,
                "findings": findings_json,
                "estimated_cost_usd": round(estimated, 8),
                "policy_version": policy.policy_version,
                "identity": {
                    "user": ctx.user,
                    "provider": ctx.provider,
                    "authenticated": ctx.authenticated,
                    "device_trusted": ctx.device_trusted,
                    "device_id": ctx.device_id,
                },
            }
        )

    return JSONResponse(status_code=upstream.status_code, content=result)
