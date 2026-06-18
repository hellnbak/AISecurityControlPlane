from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx


class ProviderError(RuntimeError):
    pass


@dataclass
class ProviderResult:
    status_code: int
    body: dict[str, Any]
    headers: dict[str, str]
    input_tokens: int = 0
    output_tokens: int = 0
    request_id: str | None = None
    provider: str | None = None


def _message_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, dict):
                if item.get("type") in {"text", "input_text", "output_text"} and isinstance(item.get("text"), str):
                    parts.append(item["text"])
                elif isinstance(item.get("text"), str):
                    parts.append(item["text"])
            elif isinstance(item, str):
                parts.append(item)
        return "\n".join(parts)
    return str(content or "")


def normalize_openai_messages(payload: dict[str, Any]) -> list[dict[str, str]]:
    messages = payload.get("messages")
    if not isinstance(messages, list):
        return []
    normalized: list[dict[str, str]] = []
    for msg in messages:
        if not isinstance(msg, dict):
            continue
        role = str(msg.get("role") or "user")
        normalized.append({"role": role, "content": _message_text(msg.get("content"))})
    return normalized


class MultiProviderClient:
    """Provider adapters for AISecurityControlPlane.

    The MVP intentionally implements a small common subset: non-streaming text chat.
    This keeps policy/routing portable while leaving room for provider-specific features later.
    """

    def __init__(self, settings: Any):
        self.settings = settings

    def configured(self, provider: str) -> bool:
        provider = provider.lower()
        if provider == "anthropic":
            return bool(self.settings.anthropic_api_key)
        if provider == "openai":
            return bool(self.settings.openai_api_key)
        if provider == "gemini":
            return bool(self.settings.gemini_api_key)
        return False

    def configured_providers(self) -> list[str]:
        return [p for p in ["anthropic", "openai", "gemini"] if self.configured(p)]

    async def chat_completions(self, *, provider: str, model: str, payload: dict[str, Any]) -> ProviderResult:
        provider = provider.lower()
        if provider == "anthropic":
            return await self._anthropic_from_chat(model, payload)
        if provider == "openai":
            return await self._openai_chat(model, payload)
        if provider == "gemini":
            return await self._gemini_from_chat(model, payload)
        raise ProviderError(f"Unsupported provider: {provider}")

    async def anthropic_messages(self, *, model: str, payload: dict[str, Any]) -> ProviderResult:
        if not self.settings.anthropic_api_key:
            raise ProviderError("ANTHROPIC_API_KEY is not configured")
        outbound = dict(payload)
        outbound["model"] = model
        url = f"{self.settings.anthropic_base_url.rstrip('/')}/v1/messages"
        headers = {
            "x-api-key": self.settings.anthropic_api_key,
            "anthropic-version": self.settings.anthropic_version,
            "content-type": "application/json",
        }
        async with httpx.AsyncClient(timeout=120.0) as client:
            upstream = await client.post(url, json=outbound, headers=headers)
        body = self._safe_json(upstream)
        usage = body.get("usage", {}) if isinstance(body, dict) else {}
        return ProviderResult(
            status_code=upstream.status_code,
            body=body,
            headers=dict(upstream.headers),
            input_tokens=int(usage.get("input_tokens") or 0),
            output_tokens=int(usage.get("output_tokens") or 0),
            request_id=upstream.headers.get("request-id") or upstream.headers.get("anthropic-request-id"),
            provider="anthropic",
        )

    async def _openai_chat(self, model: str, payload: dict[str, Any]) -> ProviderResult:
        if not self.settings.openai_api_key:
            raise ProviderError("OPENAI_API_KEY is not configured")
        outbound = dict(payload)
        outbound["model"] = model
        url = f"{self.settings.openai_base_url.rstrip('/')}/v1/chat/completions"
        headers = {
            "authorization": f"Bearer {self.settings.openai_api_key}",
            "content-type": "application/json",
        }
        async with httpx.AsyncClient(timeout=120.0) as client:
            upstream = await client.post(url, json=outbound, headers=headers)
        body = self._safe_json(upstream)
        usage = body.get("usage", {}) if isinstance(body, dict) else {}
        return ProviderResult(
            status_code=upstream.status_code,
            body=body,
            headers=dict(upstream.headers),
            input_tokens=int(usage.get("prompt_tokens") or usage.get("input_tokens") or 0),
            output_tokens=int(usage.get("completion_tokens") or usage.get("output_tokens") or 0),
            request_id=upstream.headers.get("x-request-id") or upstream.headers.get("openai-request-id"),
            provider="openai",
        )

    async def _anthropic_from_chat(self, model: str, payload: dict[str, Any]) -> ProviderResult:
        messages = normalize_openai_messages(payload)
        system_parts = [m["content"] for m in messages if m["role"] == "system" and m["content"]]
        anthropic_messages = [
            {"role": "assistant" if m["role"] == "assistant" else "user", "content": m["content"]}
            for m in messages
            if m["role"] != "system"
        ]
        outbound: dict[str, Any] = {
            "model": model,
            "messages": anthropic_messages or [{"role": "user", "content": ""}],
            "max_tokens": payload.get("max_tokens") or payload.get("max_completion_tokens") or 1024,
        }
        if system_parts:
            outbound["system"] = "\n\n".join(system_parts)
        for key in ("temperature", "top_p", "stop_sequences"):
            if key in payload:
                outbound[key] = payload[key]
        result = await self.anthropic_messages(model=model, payload=outbound)
        result.body = self._anthropic_to_openai_chat(result.body, model=model)
        return result

    async def _gemini_from_chat(self, model: str, payload: dict[str, Any]) -> ProviderResult:
        if not self.settings.gemini_api_key:
            raise ProviderError("GEMINI_API_KEY is not configured")
        messages = normalize_openai_messages(payload)
        system_instruction = None
        contents: list[dict[str, Any]] = []
        for msg in messages:
            if msg["role"] == "system":
                system_instruction = {"parts": [{"text": msg["content"]}]}
                continue
            role = "model" if msg["role"] == "assistant" else "user"
            contents.append({"role": role, "parts": [{"text": msg["content"]}]})
        outbound: dict[str, Any] = {"contents": contents or [{"role": "user", "parts": [{"text": ""}]}]}
        if system_instruction:
            outbound["systemInstruction"] = system_instruction
        generation_config: dict[str, Any] = {}
        if "temperature" in payload:
            generation_config["temperature"] = payload["temperature"]
        if "top_p" in payload:
            generation_config["topP"] = payload["top_p"]
        max_tokens = payload.get("max_tokens") or payload.get("max_completion_tokens")
        if max_tokens:
            generation_config["maxOutputTokens"] = int(max_tokens)
        if generation_config:
            outbound["generationConfig"] = generation_config
        url = f"{self.settings.gemini_base_url.rstrip('/')}/v1beta/models/{model}:generateContent"
        headers = {"x-goog-api-key": self.settings.gemini_api_key, "content-type": "application/json"}
        async with httpx.AsyncClient(timeout=120.0) as client:
            upstream = await client.post(url, json=outbound, headers=headers)
        body = self._safe_json(upstream)
        usage = body.get("usageMetadata", {}) if isinstance(body, dict) else {}
        prompt_tokens = int(usage.get("promptTokenCount") or 0)
        completion_tokens = int(usage.get("candidatesTokenCount") or 0)
        return ProviderResult(
            status_code=upstream.status_code,
            body=self._gemini_to_openai_chat(body, model=model),
            headers=dict(upstream.headers),
            input_tokens=prompt_tokens,
            output_tokens=completion_tokens,
            request_id=upstream.headers.get("x-request-id"),
            provider="gemini",
        )

    def _anthropic_to_openai_chat(self, body: dict[str, Any], model: str) -> dict[str, Any]:
        text_parts: list[str] = []
        for block in body.get("content", []) if isinstance(body, dict) else []:
            if isinstance(block, dict) and block.get("type") == "text":
                text_parts.append(str(block.get("text") or ""))
        usage = body.get("usage", {}) if isinstance(body, dict) else {}
        return {
            "id": body.get("id", "secureai-anthropic") if isinstance(body, dict) else "secureai-anthropic",
            "object": "chat.completion",
            "model": model,
            "choices": [{"index": 0, "message": {"role": "assistant", "content": "\n".join(text_parts)}, "finish_reason": body.get("stop_reason") if isinstance(body, dict) else None}],
            "usage": {
                "prompt_tokens": int(usage.get("input_tokens") or 0),
                "completion_tokens": int(usage.get("output_tokens") or 0),
                "total_tokens": int(usage.get("input_tokens") or 0) + int(usage.get("output_tokens") or 0),
            },
            "provider_response": body,
        }

    def _gemini_to_openai_chat(self, body: dict[str, Any], model: str) -> dict[str, Any]:
        text_parts: list[str] = []
        if isinstance(body, dict):
            candidates = body.get("candidates") or []
            if candidates and isinstance(candidates[0], dict):
                parts = candidates[0].get("content", {}).get("parts", [])
                for part in parts:
                    if isinstance(part, dict) and isinstance(part.get("text"), str):
                        text_parts.append(part["text"])
            usage_meta = body.get("usageMetadata", {})
        else:
            usage_meta = {}
        prompt_tokens = int(usage_meta.get("promptTokenCount") or 0)
        completion_tokens = int(usage_meta.get("candidatesTokenCount") or 0)
        return {
            "id": "secureai-gemini",
            "object": "chat.completion",
            "model": model,
            "choices": [{"index": 0, "message": {"role": "assistant", "content": "\n".join(text_parts)}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": prompt_tokens, "completion_tokens": completion_tokens, "total_tokens": prompt_tokens + completion_tokens},
            "provider_response": body,
        }

    @staticmethod
    def _safe_json(response: httpx.Response) -> dict[str, Any]:
        try:
            parsed = response.json()
            return parsed if isinstance(parsed, dict) else {"data": parsed}
        except Exception:
            return {"raw": response.text}
