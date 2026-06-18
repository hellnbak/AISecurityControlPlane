from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import httpx


@dataclass
class EndpointEvent:
    user: str
    device_id: str
    app: str
    event_type: str
    decision: str
    requested_model: str | None = None
    model_used: str | None = None
    findings: list[dict] | None = None
    reasons: list[str] | None = None
    raw_prompt_hash: str | None = None
    estimated_cost_usd: float = 0.0
    ts: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        if not data["ts"]:
            data["ts"] = time.time()
        data["findings"] = data["findings"] or []
        data["reasons"] = data["reasons"] or []
        return data


class EndpointEventBuffer:
    """Small durable event buffer for endpoint/agent mode.

    This is intentionally dependency-light so it can run on managed workstations. It writes JSONL
    locally and flushes to /v1/control/events/ingest when the control plane is reachable.
    """

    def __init__(self, spool_dir: str = "./data/endpoint-events", max_file_bytes: int = 5_000_000):
        self.spool_dir = Path(spool_dir)
        self.spool_dir.mkdir(parents=True, exist_ok=True)
        self.max_file_bytes = max_file_bytes

    def append(self, event: EndpointEvent | dict[str, Any]) -> Path:
        payload = event.to_dict() if isinstance(event, EndpointEvent) else event
        path = self._current_path()
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(payload, separators=(",", ":"), default=str) + "\n")
        return path

    def flush(self, gateway_url: str, *, batch_size: int = 250, timeout: float = 5.0) -> dict[str, Any]:
        accepted = 0
        failed_files = 0
        for path in sorted(self.spool_dir.glob("events-*.jsonl")):
            events = []
            with path.open("r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        events.append(json.loads(line))
                    if len(events) >= batch_size:
                        accepted += self._send_batch(gateway_url, events, timeout)
                        events = []
                if events:
                    accepted += self._send_batch(gateway_url, events, timeout)
            try:
                path.unlink()
            except Exception:
                failed_files += 1
        return {"accepted": accepted, "failed_files": failed_files}

    def _send_batch(self, gateway_url: str, events: list[dict[str, Any]], timeout: float) -> int:
        url = gateway_url.rstrip("/") + "/v1/control/events/ingest"
        with httpx.Client(timeout=timeout) as client:
            resp = client.post(url, json={"events": events})
            resp.raise_for_status()
            return int(resp.json().get("accepted", 0))

    def _current_path(self) -> Path:
        stamp = time.strftime("%Y%m%d%H")
        path = self.spool_dir / f"events-{stamp}.jsonl"
        if path.exists() and path.stat().st_size > self.max_file_bytes:
            path = self.spool_dir / f"events-{stamp}-{int(time.time())}.jsonl"
        return path
