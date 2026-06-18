from fastapi.testclient import TestClient

from app.main import app, providers, policy
from app.providers import ProviderResult


def test_fallback_candidates_include_chain_and_provider_defaults():
    candidates = policy.fallback_candidates("claude-sonnet-4-6")
    assert candidates[0] == {"provider": "anthropic", "model": "claude-sonnet-4-6"}
    assert {item["provider"] for item in candidates}.issuperset({"anthropic", "openai", "gemini"})


def test_chat_completions_falls_back_on_retryable_status(monkeypatch):
    client = TestClient(app)

    monkeypatch.setattr(providers, "configured", lambda provider: provider in {"anthropic", "openai", "gemini"})

    async def fake_chat_completions(*, provider: str, model: str, payload: dict):
        if provider == "anthropic":
            return ProviderResult(
                status_code=429,
                body={"error": {"message": "rate limited"}},
                headers={},
                provider="anthropic",
            )
        return ProviderResult(
            status_code=200,
            body={
                "id": "test-fallback",
                "object": "chat.completion",
                "model": model,
                "choices": [{"index": 0, "message": {"role": "assistant", "content": "fallback ok"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 5, "completion_tokens": 2, "total_tokens": 7},
            },
            headers={},
            input_tokens=5,
            output_tokens=2,
            provider=provider,
        )

    monkeypatch.setattr(providers, "chat_completions", fake_chat_completions)

    res = client.post(
        "/v1/chat/completions",
        json={"model": "auto-secure", "messages": [{"role": "user", "content": "hello"}]},
    )
    assert res.status_code == 200
    body = res.json()
    assert body["secureai"]["fallback_used"] is True
    assert body["secureai"]["provider"] == "openai"
    assert body["secureai"]["model_used"] == "gpt-4.1"
    assert body["choices"][0]["message"]["content"] == "fallback ok"


def test_provider_health_endpoint_exposes_fallback_config():
    client = TestClient(app)
    res = client.get("/v1/providers/health")
    assert res.status_code == 200
    body = res.json()
    assert "providers" in body
    assert body["fallback"]["enabled"] is True
