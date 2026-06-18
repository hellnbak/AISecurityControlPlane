# Enterprise Admin UI

The public-preview admin console is served directly by FastAPI at:

```text
http://127.0.0.1:8787/admin
```

It is intentionally static and no-build so the project can run without a Node/React toolchain.

## Features

- Usage/spend overview.
- Provider/model inventory.
- Recent audit events.
- Trusted-device inventory.
- Policy simulator.
- Policy YAML viewer, validator, and optional writer.

## Production guidance

For production-like deployments, use OIDC and device trust:

```env
AUTH_MODE=required
DEVICE_TRUST_MODE=required
ADMIN_AUTH_MODE=required
ADMIN_GROUPS=security,ai-admins
ADMIN_REQUIRE_TRUSTED_DEVICE=true
ADMIN_ENABLE_POLICY_WRITE=false
```

Keep `ADMIN_ENABLE_POLICY_WRITE=false` unless policy changes are protected by strong auth, trusted devices, audit review, and change-management procedures.
