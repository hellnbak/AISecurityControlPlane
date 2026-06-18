from __future__ import annotations

import asyncio
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .store import AuditStore


@dataclass
class AuditEvent:
    user: str
    app: str
    requested_model: str | None
    model_used: str | None
    decision: str
    reasons: list[str]
    findings: list[dict]
    input_tokens: int = 0
    output_tokens: int = 0
    estimated_cost_usd: float = 0.0
    anthropic_request_id: str | None = None
    raw_prompt_hash: str | None = None
    tenant_id: str | None = None
    device_id: str | None = None
    event_type: str | None = None
    policy_version: str | None = None
    extra: dict[str, Any] | None = None


class AuditPipeline:
    """In-process async audit pipeline with disk spillover.

    Production deployments should back this with Kafka/Kinesis/SQS. This local queue gives the MVP
    the same behavior shape: request path enqueues events quickly; a worker persists them.
    """

    def __init__(self, store: AuditStore, *, enabled: bool = True, max_size: int = 5000, spool_dir: str = "./data/audit-spool"):
        self.store = store
        self.enabled = enabled
        self.queue: asyncio.Queue[AuditEvent] = asyncio.Queue(maxsize=max_size)
        self.spool_dir = Path(spool_dir)
        self.spool_dir.mkdir(parents=True, exist_ok=True)
        self._worker_task: asyncio.Task | None = None
        self.accepted = 0
        self.spilled = 0
        self.persisted = 0
        self.failed = 0

    async def start(self) -> None:
        if self.enabled and self._worker_task is None:
            self._worker_task = asyncio.create_task(self._worker(), name="secureai-audit-pipeline")

    async def stop(self) -> None:
        if self._worker_task:
            self._worker_task.cancel()
            try:
                await self._worker_task
            except asyncio.CancelledError:
                pass
            self._worker_task = None

    def log_event(self, **kwargs: Any) -> None:
        event = AuditEvent(**kwargs)
        if not self.enabled:
            self._persist(event)
            return
        try:
            self.queue.put_nowait(event)
            self.accepted += 1
        except asyncio.QueueFull:
            self._spill(event)
            self.spilled += 1

    def metrics(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "queue_depth": self.queue.qsize() if self.enabled else 0,
            "accepted": self.accepted,
            "spilled": self.spilled,
            "persisted": self.persisted,
            "failed": self.failed,
            "spool_dir": str(self.spool_dir),
        }

    async def _worker(self) -> None:
        while True:
            event = await self.queue.get()
            try:
                self._persist(event)
                self.persisted += 1
            except Exception:
                self.failed += 1
                self._spill(event)
            finally:
                self.queue.task_done()

    def _persist(self, event: AuditEvent) -> None:
        self.store.log_event(**asdict(event))

    def _spill(self, event: AuditEvent) -> None:
        path = self.spool_dir / f"audit-spool-{datetime.now(timezone.utc).strftime('%Y%m%d%H')}.jsonl"
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(asdict(event), default=str) + "\n")
