from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path

import httpx

from event_buffer import EndpointEvent, EndpointEventBuffer


def creds_path(spool_dir: str) -> Path:
    p = Path(spool_dir)
    p.mkdir(parents=True, exist_ok=True)
    return p / "device_credentials.json"


def load_creds(spool_dir: str) -> dict:
    p = creds_path(spool_dir)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text())
    except Exception:
        return {}


def save_creds(spool_dir: str, data: dict) -> None:
    p = creds_path(spool_dir)
    p.write_text(json.dumps(data, indent=2))
    try:
        p.chmod(0o600)
    except Exception:
        pass


def enroll(args) -> dict:
    body = {
        "user": args.user,
        "device_name": args.device_name or args.device,
        "platform": args.platform,
        "serial_number": args.serial_number,
        "mdm_provider": args.mdm_provider,
        "mdm_device_id": args.mdm_device_id,
        "posture": {"demo_agent": True, "managed": bool(args.mdm_provider or args.mdm_device_id)},
    }
    r = httpx.post(
        args.gateway.rstrip("/") + "/v1/control/device/enroll",
        headers={"x-secureai-enrollment-token": args.enrollment_token},
        json=body,
        timeout=10,
    )
    r.raise_for_status()
    data = r.json()
    save_creds(args.spool_dir, data)
    return data


def auth_headers(args) -> dict[str, str]:
    creds = load_creds(args.spool_dir)
    device_id = creds.get("device_id") or args.device
    headers = {
        "x-secureai-user": args.user,
        "x-secureai-device": device_id,
        "x-secureai-groups": args.groups,
    }
    if creds.get("device_token"):
        headers["x-secureai-device-token"] = creds["device_token"]
    if args.bearer_token:
        headers["authorization"] = "Bearer " + args.bearer_token
    return headers


def main() -> None:
    parser = argparse.ArgumentParser(description="AISecurityControlPlane endpoint event-buffer and device-trust demo")
    parser.add_argument("--gateway", default=os.getenv("SECUREAI_GATEWAY", "http://127.0.0.1:8787"))
    parser.add_argument("--user", default=os.getenv("SECUREAI_USER", "steve@example.com"))
    parser.add_argument("--device", default=os.getenv("SECUREAI_DEVICE", "demo-device"))
    parser.add_argument("--device-name", default=os.getenv("SECUREAI_DEVICE_NAME", "Demo MacBook"))
    parser.add_argument("--platform", default=os.getenv("SECUREAI_PLATFORM", "macOS"))
    parser.add_argument("--serial-number", default=os.getenv("SECUREAI_SERIAL", ""))
    parser.add_argument("--mdm-provider", default=os.getenv("SECUREAI_MDM_PROVIDER", "JumpCloud"))
    parser.add_argument("--mdm-device-id", default=os.getenv("SECUREAI_MDM_DEVICE_ID", ""))
    parser.add_argument("--groups", default=os.getenv("SECUREAI_GROUPS", "security,engineering"))
    parser.add_argument("--bearer-token", default=os.getenv("SECUREAI_BEARER_TOKEN", ""))
    parser.add_argument("--enrollment-token", default=os.getenv("SECUREAI_ENROLLMENT_TOKEN", "dev-enroll-token-change-me"))
    parser.add_argument("--spool-dir", default=os.getenv("SECUREAI_EVENT_DIR", "./data/endpoint-events"))
    parser.add_argument("--enroll", action="store_true")
    parser.add_argument("--flush", action="store_true")
    args = parser.parse_args()

    if args.enroll:
        data = enroll(args)
        print({k: ("***" if k == "device_token" else v) for k, v in data.items()})
        return

    buffer = EndpointEventBuffer(args.spool_dir)

    if args.flush:
        print(buffer.flush(args.gateway))
        return

    creds = load_creds(args.spool_dir)
    device_id = creds.get("device_id") or args.device
    prompt = "demo prompt with no raw prompt logging"
    event = EndpointEvent(
        user=args.user,
        device_id=device_id,
        app="agent-demo",
        event_type="local_policy_decision",
        decision="allow",
        requested_model="auto-secure",
        model_used="claude-sonnet-4-6",
        raw_prompt_hash=hashlib.sha256(prompt.encode()).hexdigest(),
        findings=[],
        reasons=["demo endpoint event buffered locally"],
    )
    path = buffer.append(event)
    print({"buffered_to": str(Path(path).resolve())})

    # Demonstrate device-aware identity context and signed policy bundle.
    try:
        headers = auth_headers(args)
        me = httpx.get(args.gateway.rstrip("/") + "/v1/control/identity/me", headers=headers, timeout=5)
        print({"identity": me.json() if me.headers.get("content-type", "").startswith("application/json") else me.text})
        r = httpx.get(args.gateway.rstrip("/") + "/v1/control/policy/bundle", headers=headers, timeout=5)
        if r.ok:
            print({"policy_bundle_signature": r.json().get("signature", {}).get("value", "")[:16] + "..."})
        else:
            print({"policy_bundle_error": r.text})
    except Exception as e:
        print({"control_plane": f"not reachable: {type(e).__name__}"})


if __name__ == "__main__":
    main()
