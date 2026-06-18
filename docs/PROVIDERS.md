# Multi-provider support

AISecurityControlPlane now supports a provider-neutral policy layer with a first OpenAI-compatible API surface:

```text
POST /v1/chat/completions
```

The same endpoint can route to:

- Anthropic / Claude, using the native Messages API behind the adapter
- OpenAI, using `/v1/chat/completions`
- Google Gemini, using `generateContent`

## Configure keys

```env
ANTHROPIC_API_KEY=YOUR_ANTHROPIC_API_KEY
OPENAI_API_KEY=sk-...
GEMINI_API_KEY=...
```

Only configured providers can receive traffic. You can still list configured and supported providers without keys:

```bash
./scripts/test_providers.sh
```

## Model aliases

Aliases live in `policy.yaml`:

```yaml
model_aliases:
  auto-secure: claude-sonnet-4-6
  low-cost: claude-haiku-4-5
  openai-fast: gpt-4.1-mini
  gemini-fast: gemini-3.5-flash
```

Client apps can ask for an alias:

```python
from openai import OpenAI

client = OpenAI(api_key="secureai-local", base_url="http://127.0.0.1:8787/v1")

response = client.chat.completions.create(
    model="openai-fast",
    messages=[{"role": "user", "content": "Write a short summary."}],
)
```

AISecurityControlPlane resolves the alias, applies DLP/budget/model policy, chooses the provider, and then forwards the request.

## Current MVP limitations

- Non-streaming text chat only.
- Provider-specific tool/function calling is not normalized yet.
- Gemini and Anthropic responses are translated into an OpenAI-style `chat.completion` response for `/v1/chat/completions`.
- Pricing for non-Anthropic example models is intentionally set to `0.00` in `policy.yaml`; update it before relying on cost controls.
- Deterministic model control is strongest on API routes. Hosted web-app model controls remain best-effort.

## Add another provider

Add a provider adapter in `app/providers.py`, add config fields in `app/settings.py`, then register provider/model names in `policy.yaml` under `providers` and `allowed_models`.

## Fallback/failover

Provider fallback is now part of the routing policy. If the primary provider is not configured, rate-limited, temporarily unavailable, or returns a retryable status, the gateway walks the configured fallback chain.

```bash
./scripts/test_provider_failover.sh
```

See [`PROVIDER_FAILOVER.md`](PROVIDER_FAILOVER.md) for the full policy format and response metadata.
