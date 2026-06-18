from fastapi.testclient import TestClient

from app.main import app, policy


def test_provider_inventory_lists_supported_providers():
    client = TestClient(app)
    res = client.get("/v1/providers")
    assert res.status_code == 200
    names = {item["name"] for item in res.json()["providers"]}
    assert {"anthropic", "openai", "gemini"}.issubset(names)


def test_policy_resolves_provider_from_alias():
    decision = policy.decide({"model": "openai-fast", "messages": [{"role": "user", "content": "hello"}]}, [])
    assert decision.model_used == "gpt-4.1-mini"
    assert policy.provider_for_model(decision.model_used) == "openai"
