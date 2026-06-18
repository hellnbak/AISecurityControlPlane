# Identity and Device Trust

AISecurityControlPlane now supports an identity/device trust boundary for enterprise deployments.

## Modes

```env
AUTH_MODE=disabled   # local dev, trusts x-secureai-user headers
AUTH_MODE=optional   # validates Bearer OIDC tokens when present
AUTH_MODE=required   # requires a valid Bearer OIDC token

DEVICE_TRUST_MODE=optional  # includes trust state but does not block
DEVICE_TRUST_MODE=required  # requires enrolled/trusted device credentials
DEVICE_TRUST_MODE=disabled  # disables device checks
```

## Okta / OIDC

Configure an Okta OIDC application/API authorization server and set:

```env
AUTH_MODE=required
OIDC_ISSUER=https://YOUR_OKTA_DOMAIN/oauth2/default
OIDC_AUDIENCE=api://secureai
OIDC_CLIENT_ID=YOUR_CLIENT_ID
OIDC_GROUPS_CLAIM=groups
OIDC_EMAIL_CLAIM=email
```

The gateway discovers the provider metadata from:

```text
{OIDC_ISSUER}/.well-known/openid-configuration
```

and validates JWTs using the discovered JWKS URI. Validation checks:

- RS256 signature
- `iss`
- `aud`
- `exp`
- optional client id via `cid`, `azp`, or `client_id` when present
- configurable group and email claims

Requests should include:

```http
Authorization: Bearer <access_token>
```

## JumpCloud enrichment

Enable read-only enrichment:

```env
JUMPCLOUD_ENABLE_ENRICHMENT=true
JUMPCLOUD_API_KEY=YOUR_JUMPCLOUD_API_KEY
JUMPCLOUD_ORG_ID=OPTIONAL_ORG_ID
JUMPCLOUD_BASE_URL=https://console.jumpcloud.com
```

The current connector is intentionally read-only. It enriches identity/device posture using JumpCloud user and system data where available. For production, pin the exact JumpCloud endpoints and filters used by your org/API region.

## Device enrollment

Enroll a device with a bootstrap token:

```bash
curl -X POST http://127.0.0.1:8787/v1/control/device/enroll \
  -H 'content-type: application/json' \
  -H 'x-secureai-enrollment-token: dev-enroll-token-change-me' \
  -d '{
    "user": "steve@example.com",
    "device_name": "Steve MacBook",
    "platform": "macOS",
    "mdm_provider": "JumpCloud",
    "posture": {"managed": true, "disk_encrypted": true}
  }'
```

The response includes a `device_id` and one-time `device_token`. Store the token in the endpoint agent keychain/secret store. The demo stores it in `endpoint/data/endpoint-events/device_credentials.json` with `0600` permissions.

Then include:

```http
X-AISecurityControlPlane-Device: dev_xxx
X-AISecurityControlPlane-Device-Token: sdv_xxx
```

## Endpoint demo

Enroll:

```bash
cd endpoint
python agent_demo.py --enroll --user steve@example.com
```

Fetch identity context and a signed policy bundle:

```bash
python agent_demo.py --user steve@example.com
```

## Important production upgrades

The MVP device credential is intentionally simple and scalable, but a real enterprise deployment should upgrade to one or more of:

- mTLS device certificates issued through MDM
- TPM/Secure Enclave backed signing keys
- per-request signed device proofs
- CrowdStrike/Jamf/Intune/JumpCloud posture checks
- certificate revocation and rotation
- device quarantine workflows

## New endpoints

```text
POST /v1/control/device/enroll
GET  /v1/control/identity/me
GET  /v1/control/devices
GET  /v1/control/policy/bundle
```

`/v1/control/policy/bundle` now includes identity and device trust fields in the signed payload.
