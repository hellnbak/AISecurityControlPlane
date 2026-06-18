# AISecurityControlPlane

AISecurityControlPlane is a **source-available, provider-neutral AI usage-control gateway** for enterprises that want policy enforcement around AI model usage, cost, DLP/secrets, auditability, identity, and device trust.

> Public preview: this project is not production-ready. Hosted web-app controls are best-effort and may break when a provider changes its frontend or request format. Deterministic model routing is strongest through the API gateway path.

## License

This project is licensed under **Functional Source License 1.1, Apache 2.0 Future License (FSL-1.1-ALv2)**.

This is **source-available software**, not OSI-approved open source. Commercial use that competes with AISecurityControlPlane or offers it as a hosted/managed AI security gateway, AI governance, AI DLP, AI model-routing, or AI cost-control product/service requires a commercial license before the Change Date. See [`LICENSE`](LICENSE), [`LICENSE_SUMMARY.md`](LICENSE_SUMMARY.md), and [`COMMERCIAL-LICENSE.md`](COMMERCIAL-LICENSE.md).

## What it does

- OpenAI-compatible `/v1/chat/completions` gateway.
- Provider adapters for Anthropic/Claude, OpenAI, and Google Gemini.
- Provider fallback/failover and budget-aware downgrade policy.
- Claude.ai browser extension controls for paste, upload, request observation, and best-effort model rewrite/block.
- DLP/secrets scanning for prompts, web requests, and file names.
- Per-user budget reservations with Redis fallback support.
- SQLite local mode and Postgres-ready audit store.
- Signed endpoint policy bundles.
- Endpoint event buffering demo.
- Okta/OIDC identity validation scaffolding.
- JumpCloud user/device enrichment scaffolding.
- Device enrollment and trusted-device checks.
- Static enterprise admin console at `/admin`.
- Docker Compose and Kubernetes starter deployment.

## Architecture

```text
Browser / IDE / CLI / AI app
        |
        v
AISecurityControlPlane endpoint plane
  - browser extension
  - local policy cache
  - local DLP/secrets scan
  - optional API proxy path
  - local event buffer
        |
        v
AISecurityControlPlane control plane
  - policy bundle service
  - web/API policy evaluation
  - model rewrite/block decisions
  - budget reservations
  - audit ingestion
  - provider routing/fallback
  - admin console/API
        |
        v
AI providers
  - Anthropic / Claude
  - OpenAI
  - Google Gemini
```

## Quickstart

```bash
git clone https://github.com/hellnbak/AISecurityControlPlane.git
cd AISecurityControlPlane
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
make dev
```

Open:

```text
http://127.0.0.1:8787/admin
```

Health check:

```bash
curl http://127.0.0.1:8787/health | python -m json.tool
```

## Configure providers

Edit `.env` and set the provider keys you want to test:

```env
ANTHROPIC_API_KEY=
OPENAI_API_KEY=
GEMINI_API_KEY=
```

No provider keys are required for policy simulation, admin UI review, or many local tests.

## OpenAI-compatible API example

```python
from openai import OpenAI

client = OpenAI(
    api_key="aiscp-local",
    base_url="http://127.0.0.1:8787/v1",
)

response = client.chat.completions.create(
    model="auto-secure",
    messages=[{"role": "user", "content": "Write a short security summary."}],
)
print(response)
```

## Useful endpoints

```text
GET  /health
GET  /admin
GET  /v1/providers
GET  /v1/providers/health
POST /v1/chat/completions
POST /v1/messages
POST /v1/web/evaluate
GET  /v1/control/policy/bundle
POST /v1/control/events/ingest
POST /v1/control/device/enroll
GET  /v1/audit/recent
GET  /v1/admin/overview
GET  /v1/admin/audit
GET  /v1/admin/models
GET  /v1/admin/devices
GET  /v1/admin/policy
POST /v1/admin/policy/validate
PUT  /v1/admin/policy
POST /v1/admin/simulate
```

## Run tests

```bash
make check
```

Or directly:

```bash
python -m compileall -q app endpoint
pytest -q
```

Manual scripts:

```bash
./scripts/test_admin_api.sh
./scripts/test_providers.sh
./scripts/test_provider_failover.sh
./scripts/test_model_control.sh
./scripts/test_web_evaluate.sh
./scripts/test_policy_bundle.sh
./scripts/test_event_ingest.sh
```

## Docker Compose local stack

```bash
cd deploy/local
docker compose up --build
```

This starts the gateway with Postgres and Redis using the local compose configuration.

## Enterprise admin UI

The admin console is intentionally static and no-build for public preview:

```text
http://127.0.0.1:8787/admin
```

It includes:

- usage/spend overview
- provider/model inventory
- recent audit events
- device inventory
- policy simulator
- policy validation and optional policy save

For production-like mode:

```env
AUTH_MODE=required
DEVICE_TRUST_MODE=required
ADMIN_AUTH_MODE=required
ADMIN_REQUIRE_TRUSTED_DEVICE=true
ADMIN_ENABLE_POLICY_WRITE=false
```

## Known limitations

- Hosted Claude.ai controls are best-effort.
- Browser controls can be bypassed on unmanaged devices.
- Native API gateway routing is the deterministic enforcement path.
- Streaming, tools/function calling, multimodal inputs, and file upload scanning are not fully normalized yet.
- Device tokens are MVP credentials; production should move to mTLS, MDM-issued certificates, or hardware-backed device attestation.
- SQLite mode is for local development only.
- No formal security review has been completed.

## Docs

- [`docs/PROVIDERS.md`](docs/PROVIDERS.md)
- [`docs/PROVIDER_FAILOVER.md`](docs/PROVIDER_FAILOVER.md)
- [`docs/IDENTITY_DEVICE_TRUST.md`](docs/IDENTITY_DEVICE_TRUST.md)
- [`docs/ENTERPRISE_ADMIN_UI.md`](docs/ENTERPRISE_ADMIN_UI.md)
- [`docs/SCALING_PLAN.md`](docs/SCALING_PLAN.md)
- [`docs/PUBLIC_RELEASE_CHECKLIST.md`](docs/PUBLIC_RELEASE_CHECKLIST.md)
- [`ROADMAP.md`](ROADMAP.md)

```
