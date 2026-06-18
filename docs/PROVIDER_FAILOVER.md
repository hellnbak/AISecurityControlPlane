# Provider fallback and failover

AISecurityControlPlane supports policy-driven provider fallback for the OpenAI-compatible route:

```text
POST /v1/chat/completions
```

The gateway first resolves the requested model through policy aliases and routing rules, then builds an ordered fallback chain. It tries each configured provider/model until one returns a non-retryable response.

## What triggers fallback

By default, fallback is attempted when a provider is:

- not configured locally
- unavailable because the API key is missing
- rate-limited (`429`)
- temporarily unavailable (`408`, `409`, `425`, `5xx`)
- raising an adapter/provider exception

Fallback is controlled by `policy.yaml`:

```yaml
routing:
  fallback:
    enabled: true
    max_attempts: 3
    retry_status_codes: [408, 409, 425, 429, 500, 502, 503, 504]
    fallback_order: [anthropic, openai, gemini]
    chains:
      claude-sonnet-4-6:
        - gpt-4.1
        - gemini-3.5-pro
```

## Budget-aware downgrades

The gateway can also downgrade a model before provider selection when the user is approaching their configured budget.

```yaml
routing:
  fallback:
    budget_downgrade:
      enabled: true
      threshold_pct: 0.80
      default_model: claude-haiku-4-5
      models:
        claude-opus-4-8: claude-sonnet-4-6
        claude-sonnet-4-6: claude-haiku-4-5
        gpt-4.1: gpt-4.1-mini
        gemini-3.5-pro: gemini-3.5-flash
```

This lets an enterprise move users from premium models to lower-cost models before blocking them completely.

## Provider health endpoint

```bash
curl http://127.0.0.1:8787/v1/providers/health | python -m json.tool
```

The endpoint reports configured providers, provider defaults, and the active fallback policy. The MVP intentionally does not perform remote provider pings by default, to avoid leaking API keys, adding startup latency, or generating provider traffic just by opening the admin UI.

## Response metadata

When fallback is used, responses include AISecurityControlPlane metadata:

```json
{
  "secureai": {
    "fallback_used": true,
    "attempts": [
      {"provider": "anthropic", "model": "claude-sonnet-4-6", "status_code": 429},
      {"provider": "openai", "model": "gpt-4.1", "status_code": 200}
    ],
    "provider": "openai",
    "model_used": "gpt-4.1"
  }
}
```

Audit events also record the fallback attempts and the final selected provider/model.
