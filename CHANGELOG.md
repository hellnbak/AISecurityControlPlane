# Changelog

## 0.3.0 - 2026-06-17

Initial public-prep release candidate.

- Claude API gateway MVP
- Claude.ai browser extension controls
- Hosted-web model rewrite/block support where request bodies expose model fields
- Optional managed TLS proxy scaffold
- Postgres-ready audit store
- Redis-ready budget reservations
- Signed policy bundles
- Endpoint event buffering
- Okta/OIDC identity scaffold
- JumpCloud enrichment scaffold
- Device enrollment and trust tokens
- Docker Compose local stack
- Kubernetes starter deployment
- FSL-1.1-ALv2 source-available license files

## 0.5.0 - Multi-provider gateway

- Added provider adapters for Anthropic, OpenAI, and Google Gemini.
- Added OpenAI-compatible `POST /v1/chat/completions` route.
- Added `/v1/providers` provider/model inventory endpoint.
- Added provider aliases in `policy.yaml` for OpenAI and Gemini examples.
- Added `docs/PROVIDERS.md` and provider test scripts.

## v0.6.0 - Provider fallback and failover

Added:
- Policy-driven provider fallback chains for `/v1/chat/completions`.
- Retry/failover support for missing providers, adapter exceptions, rate limits, and retryable HTTP status codes.
- Budget-aware model downgrade rules.
- `/v1/providers/health` endpoint.
- Fallback attempt metadata in responses and audit events.
- `docs/PROVIDER_FAILOVER.md` and `scripts/test_provider_failover.sh`.
- Tests covering fallback chain generation and retryable provider failover.
