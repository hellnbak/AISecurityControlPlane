from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import yaml

from .scanners import Finding
from .signing import sha256_hex, signed_envelope


@dataclass
class PolicyDecision:
    decision: str  # allow, allow_with_warning, block
    reasons: list[str]
    requested_model: str
    model_used: str | None
    max_tokens: int | None
    rewrite_request_body: str | None = None
    rewrite_applied_fields: list[str] | None = None


MODEL_FIELD_NAMES = {
    "model",
    "model_id",
    "model_name",
    "model_slug",
    "selected_model",
    "selectedModel",
    "claude_model",
    "completion_model",
}


class PolicyEngine:
    def __init__(self, policy_path: str):
        self.path = Path(policy_path)
        self.reload()

    def reload(self) -> None:
        with self.path.open("r", encoding="utf-8") as f:
            self.policy: dict[str, Any] = yaml.safe_load(f) or {}
        self.policy_version = self.policy.get("version") or sha256_hex(self.policy)[:16]

    def policy_hash(self) -> str:
        return sha256_hex(self.policy)

    def policy_bundle(
        self,
        *,
        user: str,
        device_id: str,
        groups: list[str],
        tenant_id: str,
        signing_secret: str,
        ttl_minutes: int | None = None,
        authenticated: bool = False,
        provider: str = "local",
        device_trusted: bool = False,
        device_posture: dict[str, Any] | None = None,
        jumpcloud: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        control = self.policy.get("control_plane", {})
        ttl = int(ttl_minutes or control.get("policy_bundle_ttl_minutes", 1440))
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=ttl)
        payload = {
            "tenant_id": tenant_id,
            "user": user,
            "device_id": device_id,
            "groups": groups,
            "authenticated": authenticated,
            "identity_provider": provider,
            "device_trusted": device_trusted,
            "device_posture": device_posture or {},
            "jumpcloud": jumpcloud or {},
            "policy_version": self.policy_version,
            "policy_hash": self.policy_hash(),
            "issued_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": expires_at.isoformat(),
            "gateway_url": control.get("gateway_url", "http://127.0.0.1:8787"),
            "fail_modes": self.policy.get("fail_modes", {}),
            "defaults": self.policy.get("defaults", {}),
            "providers": self.policy.get("providers", {}),
            "model_aliases": self.policy.get("model_aliases", {}),
            "allowed_models": self.policy.get("allowed_models", []),
            "blocked_models": self.policy.get("blocked_models", []),
            "security": self.policy.get("security", {}),
            "web_controls": self.web_controls(),
            "web_model_control": self.web_model_control(),
            "routing": self.policy.get("routing", {}),
            "sensitive_uploads": self.policy.get("sensitive_uploads", {}),
        }
        return signed_envelope(payload, signing_secret, key_id=control.get("signing_key_id", "local-dev"))

    def resolve_model(self, requested_model: str | None, payload: dict, findings: list[Finding]) -> str:
        defaults = self.policy.get("defaults", {})
        aliases = self.policy.get("model_aliases", {})
        routing = self.policy.get("routing", {})

        requested = requested_model or defaults.get("default_model")
        resolved = aliases.get(requested, requested)

        prompt = str(payload).lower()
        has_pii = any(f.type in {"ssn", "credit_card", "email_address"} for f in findings)
        has_security_code_review = "vulnerability" in prompt or "code review" in prompt or "cve" in prompt
        looks_like_summary = "summarize" in prompt or "summary" in prompt

        if has_pii:
            return routing.get("confidential_data_model", resolved)
        if has_security_code_review:
            return routing.get("security_code_review_model", resolved)
        if looks_like_summary and not findings:
            return routing.get("public_summarization_model", resolved)
        return resolved

    def decide(self, payload: dict, findings: list[Finding]) -> PolicyDecision:
        defaults = self.policy.get("defaults", {})
        security = self.policy.get("security", {})
        requested_model = payload.get("model") or defaults.get("default_model")
        model_used = self.resolve_model(requested_model, payload, findings)
        allowed_models = set(self.policy.get("allowed_models", []))
        blocked_models = set(self.policy.get("blocked_models", []))
        reasons: list[str] = []

        if defaults.get("block_streaming", True) and payload.get("stream") is True:
            return PolicyDecision("block", ["Streaming is disabled in MVP policy"], requested_model, None, None)

        if requested_model in blocked_models or model_used in blocked_models:
            return PolicyDecision("block", [f"Model blocked by policy: {requested_model}"], requested_model, None, None)

        if allowed_models and requested_model not in allowed_models and model_used not in allowed_models:
            return PolicyDecision("block", [f"Model not in allowed list: {requested_model}"], requested_model, None, None)

        has_secret = any(f.type in {"aws_access_key_id", "github_token", "slack_token", "jwt"} for f in findings)
        has_private_key = any(f.type == "private_key" for f in findings)
        has_sensitive_upload = any(f.type == "sensitive_file_upload" for f in findings)
        has_pii = any(f.type in {"ssn", "credit_card", "email_address"} for f in findings)
        has_jailbreak = any(f.type == "prompt_injection_or_jailbreak" for f in findings)

        if has_private_key and security.get("block_on_private_key", True):
            return PolicyDecision("block", ["Private key material detected"], requested_model, None, None)
        if has_secret and security.get("block_on_secret", True):
            return PolicyDecision("block", ["Credential or token-like secret detected"], requested_model, None, None)
        if has_sensitive_upload and security.get("block_on_sensitive_upload", True):
            return PolicyDecision("block", ["Sensitive-looking file upload detected"], requested_model, None, None)
        if has_jailbreak and security.get("block_on_jailbreak", False):
            return PolicyDecision("block", ["Prompt-injection or jailbreak pattern detected"], requested_model, None, None)
        if has_pii and security.get("warn_on_pii", True):
            reasons.append("PII-like content detected; request allowed with warning")
            return PolicyDecision("allow_with_warning", reasons, requested_model, model_used, payload.get("max_tokens"))

        return PolicyDecision("allow", reasons, requested_model, model_used, payload.get("max_tokens"))

    def decide_web(self, payload: dict, findings: list[Finding]) -> PolicyDecision:
        """Decision path for Claude.ai browser/TLS interception events.

        Reuses core DLP/model policy and then applies hosted-web model control. If a Claude.ai
        request body exposes a model-like JSON field, the gateway can return a rewritten body.
        """
        web_controls = self.web_controls()
        if not web_controls.get("enabled", True):
            defaults = self.policy.get("defaults", {})
            requested_model = payload.get("model") or defaults.get("default_model")
            return PolicyDecision("allow", ["Web controls disabled"], requested_model, requested_model, None)

        event = payload.get("web_event") or {}
        event_type = str(event.get("event_type") or "web_event")

        if event_type in {"file_change", "drop"} and not web_controls.get("inspect_file_uploads", True):
            defaults = self.policy.get("defaults", {})
            requested_model = payload.get("model") or defaults.get("default_model")
            return PolicyDecision("allow", ["File upload inspection disabled"], requested_model, requested_model, None)

        decision = self.decide(payload, findings)
        if decision.decision == "block":
            return decision

        model_decision = self._evaluate_hosted_model_request(payload)
        if model_decision:
            return model_decision

        has_jailbreak = any(f.type == "prompt_injection_or_jailbreak" for f in findings)
        if has_jailbreak and web_controls.get("warn_on_jailbreak", True):
            reasons = list(decision.reasons) + ["Prompt-injection-like content observed in Claude.ai web interaction"]
            return PolicyDecision("allow_with_warning", reasons, decision.requested_model, decision.model_used, decision.max_tokens)

        return decision

    def _evaluate_hosted_model_request(self, payload: dict) -> PolicyDecision | None:
        model_control = self.web_model_control()
        if not model_control.get("enabled", False):
            return None
        request_body = payload.get("web_event", {}).get("request_body") or payload.get("request_body")
        if not isinstance(request_body, str) or not request_body.strip():
            return None
        try:
            parsed = json.loads(request_body)
        except Exception:
            return None

        observed: list[tuple[str, str]] = []
        self._collect_model_fields(parsed, observed)
        if not observed:
            return None

        forced_model = str(model_control.get("forced_model") or self.policy.get("defaults", {}).get("default_model"))
        allowed_patterns = [str(x).lower() for x in model_control.get("allowed_model_patterns", [])]
        blocked_patterns = [str(x).lower() for x in model_control.get("blocked_model_patterns", [])]
        mode = str(model_control.get("mode") or "rewrite_if_possible")

        requested_model = observed[0][1]
        lower = requested_model.lower()
        is_blocked = any(p in lower for p in blocked_patterns) if blocked_patterns else False
        is_allowed = any(p in lower for p in allowed_patterns) if allowed_patterns else True
        if not is_blocked and is_allowed:
            return PolicyDecision("allow", [f"Hosted Claude.ai model allowed: {requested_model}"], requested_model, requested_model, None)

        if mode in {"rewrite", "rewrite_if_possible"}:
            clone = copy.deepcopy(parsed)
            rewritten_fields: list[str] = []
            self._rewrite_model_fields(clone, rewritten_fields, forced_model)
            if rewritten_fields:
                return PolicyDecision(
                    "allow_with_warning",
                    [f"Hosted Claude.ai model rewritten from {requested_model} to {forced_model}"],
                    requested_model,
                    forced_model,
                    None,
                    rewrite_request_body=json.dumps(clone, separators=(",", ":")),
                    rewrite_applied_fields=rewritten_fields,
                )

        return PolicyDecision(
            "block",
            [f"Hosted Claude.ai model blocked by policy: {requested_model}"],
            requested_model,
            None,
            None,
        )

    def _collect_model_fields(self, obj: Any, out: list[tuple[str, str]], path: str = "$") -> None:
        if isinstance(obj, dict):
            for key, value in obj.items():
                child_path = f"{path}.{key}"
                if key in MODEL_FIELD_NAMES and isinstance(value, str):
                    out.append((child_path, value))
                self._collect_model_fields(value, out, child_path)
        elif isinstance(obj, list):
            for idx, item in enumerate(obj):
                self._collect_model_fields(item, out, f"{path}[{idx}]")

    def _rewrite_model_fields(self, obj: Any, out: list[str], forced_model: str, path: str = "$") -> None:
        if isinstance(obj, dict):
            for key, value in obj.items():
                child_path = f"{path}.{key}"
                if key in MODEL_FIELD_NAMES and isinstance(value, str):
                    obj[key] = forced_model
                    out.append(child_path)
                else:
                    self._rewrite_model_fields(value, out, forced_model, child_path)
        elif isinstance(obj, list):
            for idx, item in enumerate(obj):
                self._rewrite_model_fields(item, out, forced_model, f"{path}[{idx}]")

    def provider_for_model(self, model: str | None) -> str:
        model = str(model or "")
        providers = self.policy.get("providers", {})
        for provider_name, provider_config in providers.items():
            models = provider_config.get("models", []) if isinstance(provider_config, dict) else []
            if model in models:
                return str(provider_name)
        explicit = self.policy.get("model_providers", {})
        if model in explicit:
            return str(explicit[model])
        if model.startswith("claude-"):
            return "anthropic"
        if model.startswith("gpt-") or model.startswith("o"):
            return "openai"
        if model.startswith("gemini-"):
            return "gemini"
        return str(self.policy.get("defaults", {}).get("default_provider", "anthropic"))

    def provider_default_model(self, provider_name: str) -> str | None:
        provider_config = self.policy.get("providers", {}).get(provider_name, {})
        if isinstance(provider_config, dict):
            default_model = provider_config.get("default_model")
            if default_model:
                return str(default_model)
            models = provider_config.get("models") or []
            if models:
                return str(models[0])
        return None

    def fallback_config(self) -> dict[str, Any]:
        routing = self.policy.get("routing", {})
        return routing.get(
            "fallback",
            {
                "enabled": True,
                "retry_status_codes": [408, 409, 425, 429, 500, 502, 503, 504],
                "max_attempts": 3,
                "fallback_order": routing.get("provider_fallback_order", ["anthropic", "openai", "gemini"]),
            },
        )

    def fallback_candidates(self, model: str | None) -> list[dict[str, str]]:
        """Return ordered fallback candidates as {provider, model}.

        The primary model is always first. Specific model chains win over provider-level
        defaults, then provider fallback order fills in any remaining providers.
        """
        model = str(model or self.policy.get("defaults", {}).get("default_model", ""))
        fallback = self.fallback_config()
        if not fallback.get("enabled", True):
            return [{"provider": self.provider_for_model(model), "model": model}]

        chains = fallback.get("chains", {}) if isinstance(fallback, dict) else {}
        configured_chain = chains.get(model) if isinstance(chains, dict) else None
        models: list[str] = [model]
        if isinstance(configured_chain, list):
            models.extend(str(item) for item in configured_chain if item)

        seen_models: set[str] = set()
        candidates: list[dict[str, str]] = []
        for candidate_model in models:
            if candidate_model in seen_models:
                continue
            seen_models.add(candidate_model)
            candidates.append({"provider": self.provider_for_model(candidate_model), "model": candidate_model})

        seen_providers = {item["provider"] for item in candidates}
        fallback_order = fallback.get("fallback_order") or self.policy.get("routing", {}).get("provider_fallback_order", [])
        for provider_name in fallback_order:
            provider_name = str(provider_name)
            if provider_name in seen_providers:
                continue
            default_model = self.provider_default_model(provider_name)
            if default_model:
                seen_providers.add(provider_name)
                candidates.append({"provider": provider_name, "model": default_model})

        max_attempts = int(fallback.get("max_attempts", len(candidates)) or len(candidates))
        return candidates[:max(max_attempts, 1)]

    def should_fallback_status(self, status_code: int) -> bool:
        fallback = self.fallback_config()
        retryable = set(int(code) for code in fallback.get("retry_status_codes", []))
        return int(status_code) in retryable or int(status_code) >= 500

    def budget_downgrade_model(self, model: str | None, projected_monthly_usd: float, monthly_budget_usd: float) -> str | None:
        fallback = self.fallback_config()
        budget_rules = fallback.get("budget_downgrade", {}) if isinstance(fallback, dict) else {}
        if not budget_rules.get("enabled", False) or not monthly_budget_usd:
            return None
        threshold = float(budget_rules.get("threshold_pct", 0.8))
        if projected_monthly_usd / monthly_budget_usd < threshold:
            return None
        chains = budget_rules.get("models", {})
        current = str(model or "")
        if isinstance(chains, dict) and current in chains:
            return str(chains[current])
        default_model = budget_rules.get("default_model")
        return str(default_model) if default_model else None

    def supported_providers(self) -> dict[str, Any]:
        return self.policy.get("providers", {})

    def cap_chat_tokens(self, payload: dict) -> int:
        defaults = self.policy.get("defaults", {})
        configured_cap = int(defaults.get("max_output_tokens", 4096))
        requested = int(payload.get("max_tokens") or payload.get("max_completion_tokens") or configured_cap)
        return min(requested, configured_cap)

    def cap_max_tokens(self, payload: dict) -> int:
        defaults = self.policy.get("defaults", {})
        configured_cap = int(defaults.get("max_output_tokens", 4096))
        requested = int(payload.get("max_tokens") or configured_cap)
        return min(requested, configured_cap)

    def pricing_for_model(self, model: str) -> dict[str, float]:
        pricing = self.policy.get("pricing_per_mtok", {})
        return pricing.get(model, {"input": 0.0, "output": 0.0})

    def daily_budget(self) -> float:
        return float(self.policy.get("defaults", {}).get("daily_budget_usd_per_user", 10.0))

    def monthly_budget(self) -> float:
        return float(self.policy.get("defaults", {}).get("monthly_budget_usd_per_user", 100.0))

    def web_controls(self) -> dict[str, Any]:
        return self.policy.get(
            "web_controls",
            {
                "enabled": True,
                "inspect_paste": True,
                "inspect_typing_before_submit": True,
                "inspect_file_uploads": True,
                "inspect_fetch": True,
                "inspect_xhr": True,
                "fail_closed_on_gateway_unavailable": True,
                "max_body_chars": 200000,
            },
        )

    def web_model_control(self) -> dict[str, Any]:
        return self.policy.get(
            "web_model_control",
            {
                "enabled": False,
                "mode": "rewrite_if_possible",
                "forced_model": self.policy.get("defaults", {}).get("default_model", "claude-sonnet-4-6"),
                "allowed_model_patterns": ["sonnet", "haiku"],
                "blocked_model_patterns": ["opus"],
            },
        )
