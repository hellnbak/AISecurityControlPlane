from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import (
    JSON,
    DateTime,
    Float,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    create_engine,
    func,
    insert,
    select,
    update,
)
from sqlalchemy.engine import Engine


metadata = MetaData()

audit_events = Table(
    "audit_events",
    metadata,
    # Big enough for Postgres, still works on SQLite.
    # For production, replace create_all with Alembic migrations.
    # SQLAlchemy maps Integer PK/autoincrement portably here.
    __import__("sqlalchemy").Column("id", Integer, primary_key=True, autoincrement=True),
    __import__("sqlalchemy").Column("ts", DateTime(timezone=True), nullable=False, index=True),
    __import__("sqlalchemy").Column("tenant_id", String(128), nullable=False, default="demo-org", index=True),
    __import__("sqlalchemy").Column("user", String(320), nullable=False, index=True),
    __import__("sqlalchemy").Column("device_id", String(256), nullable=True, index=True),
    __import__("sqlalchemy").Column("app", String(256), nullable=False, index=True),
    __import__("sqlalchemy").Column("event_type", String(128), nullable=True, index=True),
    __import__("sqlalchemy").Column("requested_model", String(256), nullable=True),
    __import__("sqlalchemy").Column("model_used", String(256), nullable=True, index=True),
    __import__("sqlalchemy").Column("decision", String(64), nullable=False, index=True),
    __import__("sqlalchemy").Column("policy_version", String(128), nullable=True, index=True),
    __import__("sqlalchemy").Column("reasons_json", Text, nullable=False),
    __import__("sqlalchemy").Column("findings_json", Text, nullable=False),
    __import__("sqlalchemy").Column("input_tokens", Integer, default=0),
    __import__("sqlalchemy").Column("output_tokens", Integer, default=0),
    __import__("sqlalchemy").Column("estimated_cost_usd", Float, default=0.0),
    __import__("sqlalchemy").Column("anthropic_request_id", String(256), nullable=True),
    __import__("sqlalchemy").Column("raw_prompt_hash", String(128), nullable=True),
    __import__("sqlalchemy").Column("extra_json", Text, nullable=True),
)


device_enrollments = Table(
    "device_enrollments",
    metadata,
    __import__("sqlalchemy").Column("device_id", String(256), primary_key=True),
    __import__("sqlalchemy").Column("tenant_id", String(128), nullable=False, default="demo-org", index=True),
    __import__("sqlalchemy").Column("user", String(320), nullable=False, index=True),
    __import__("sqlalchemy").Column("device_token_hash", String(128), nullable=False),
    __import__("sqlalchemy").Column("status", String(64), nullable=False, default="trusted", index=True),
    __import__("sqlalchemy").Column("device_name", String(256), nullable=True),
    __import__("sqlalchemy").Column("platform", String(128), nullable=True),
    __import__("sqlalchemy").Column("serial_number", String(256), nullable=True, index=True),
    __import__("sqlalchemy").Column("mdm_provider", String(128), nullable=True),
    __import__("sqlalchemy").Column("mdm_device_id", String(256), nullable=True, index=True),
    __import__("sqlalchemy").Column("public_key_pem", Text, nullable=True),
    __import__("sqlalchemy").Column("posture_json", Text, nullable=True),
    __import__("sqlalchemy").Column("enrolled_at", DateTime(timezone=True), nullable=False),
    __import__("sqlalchemy").Column("last_seen_at", DateTime(timezone=True), nullable=True),
)

class AuditStore:
    """Audit event store with SQLite-by-default and Postgres-ready behavior.

    Local MVP usage:
        AuditStore(sqlite_path="secureai_gateway.db")

    Scaled/control-plane usage:
        AuditStore(database_url="postgresql+psycopg://...")
    """

    def __init__(self, sqlite_path: str = "secureai_gateway.db", database_url: str = "", tenant_id: str = "demo-org"):
        self.tenant_id = tenant_id
        self.database_url = database_url or f"sqlite:///{Path(sqlite_path).expanduser()}"
        connect_args = {"check_same_thread": False} if self.database_url.startswith("sqlite") else {}
        self.engine: Engine = create_engine(self.database_url, future=True, pool_pre_ping=True, connect_args=connect_args)
        self._init()

    def _init(self) -> None:
        metadata.create_all(self.engine)

    def log_event(
        self,
        *,
        user: str,
        app: str,
        requested_model: str | None,
        model_used: str | None,
        decision: str,
        reasons: list[str],
        findings: list[dict],
        input_tokens: int = 0,
        output_tokens: int = 0,
        estimated_cost_usd: float = 0.0,
        anthropic_request_id: str | None = None,
        raw_prompt_hash: str | None = None,
        tenant_id: str | None = None,
        device_id: str | None = None,
        event_type: str | None = None,
        policy_version: str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> None:
        row = {
            "ts": datetime.now(timezone.utc),
            "tenant_id": tenant_id or self.tenant_id,
            "user": user,
            "device_id": device_id,
            "app": app,
            "event_type": event_type,
            "requested_model": requested_model,
            "model_used": model_used,
            "decision": decision,
            "policy_version": policy_version,
            "reasons_json": json.dumps(reasons),
            "findings_json": json.dumps(findings),
            "input_tokens": int(input_tokens or 0),
            "output_tokens": int(output_tokens or 0),
            "estimated_cost_usd": float(estimated_cost_usd or 0.0),
            "anthropic_request_id": anthropic_request_id,
            "raw_prompt_hash": raw_prompt_hash,
            "extra_json": json.dumps(extra or {}),
        }
        with self.engine.begin() as conn:
            conn.execute(insert(audit_events).values(**row))

    def spend_since(self, user: str, iso_or_dt: str | datetime, tenant_id: str | None = None) -> float:
        if isinstance(iso_or_dt, str):
            since = datetime.fromisoformat(iso_or_dt.replace("Z", "+00:00"))
        else:
            since = iso_or_dt
        tenant = tenant_id or self.tenant_id
        stmt = select(func.coalesce(func.sum(audit_events.c.estimated_cost_usd), 0.0)).where(
            audit_events.c.user == user,
            audit_events.c.tenant_id == tenant,
            audit_events.c.ts >= since,
        )
        with self.engine.begin() as conn:
            return float(conn.execute(stmt).scalar() or 0.0)

    def recent_events(self, limit: int = 50, tenant_id: str | None = None) -> list[dict]:
        tenant = tenant_id or self.tenant_id
        stmt = (
            select(audit_events)
            .where(audit_events.c.tenant_id == tenant)
            .order_by(audit_events.c.id.desc())
            .limit(min(int(limit or 50), 500))
        )
        with self.engine.begin() as conn:
            rows = conn.execute(stmt).mappings().all()
        results: list[dict] = []
        for row in rows:
            item = dict(row)
            item["ts"] = item["ts"].isoformat() if item.get("ts") else None
            for key in ("reasons_json", "findings_json", "extra_json"):
                if key in item and isinstance(item[key], str):
                    try:
                        item[key.replace("_json", "")] = json.loads(item[key])
                    except Exception:
                        item[key.replace("_json", "")] = item[key]
            results.append(item)
        return results

    def decision_counts_since(self, iso_or_dt: str | datetime, tenant_id: str | None = None) -> dict[str, int]:
        if isinstance(iso_or_dt, str):
            since = datetime.fromisoformat(iso_or_dt.replace("Z", "+00:00"))
        else:
            since = iso_or_dt
        tenant = tenant_id or self.tenant_id
        stmt = (
            select(audit_events.c.decision, func.count())
            .where(audit_events.c.tenant_id == tenant, audit_events.c.ts >= since)
            .group_by(audit_events.c.decision)
        )
        with self.engine.begin() as conn:
            return {str(decision): int(count) for decision, count in conn.execute(stmt).all()}

    def upsert_device(
        self,
        *,
        device_id: str,
        user: str,
        device_token_hash: str,
        status: str = "trusted",
        device_name: str | None = None,
        platform: str | None = None,
        serial_number: str | None = None,
        mdm_provider: str | None = None,
        mdm_device_id: str | None = None,
        public_key_pem: str | None = None,
        posture: dict[str, Any] | None = None,
        enrolled_at: datetime | None = None,
        last_seen_at: datetime | None = None,
    ) -> None:
        now = datetime.now(timezone.utc)
        row = {
            "device_id": device_id,
            "tenant_id": self.tenant_id,
            "user": user,
            "device_token_hash": device_token_hash,
            "status": status,
            "device_name": device_name,
            "platform": platform,
            "serial_number": serial_number,
            "mdm_provider": mdm_provider,
            "mdm_device_id": mdm_device_id,
            "public_key_pem": public_key_pem,
            "posture_json": json.dumps(posture or {}),
            "enrolled_at": enrolled_at or now,
            "last_seen_at": last_seen_at or now,
        }
        with self.engine.begin() as conn:
            existing = conn.execute(
                select(device_enrollments.c.device_id).where(
                    device_enrollments.c.device_id == device_id,
                    device_enrollments.c.tenant_id == self.tenant_id,
                )
            ).scalar()
            if existing:
                conn.execute(
                    update(device_enrollments)
                    .where(device_enrollments.c.device_id == device_id, device_enrollments.c.tenant_id == self.tenant_id)
                    .values(**row)
                )
            else:
                conn.execute(insert(device_enrollments).values(**row))

    def get_device(self, device_id: str, tenant_id: str | None = None) -> dict[str, Any] | None:
        tenant = tenant_id or self.tenant_id
        stmt = select(device_enrollments).where(
            device_enrollments.c.device_id == device_id,
            device_enrollments.c.tenant_id == tenant,
        )
        with self.engine.begin() as conn:
            row = conn.execute(stmt).mappings().first()
        if not row:
            return None
        item = dict(row)
        for key in ("enrolled_at", "last_seen_at"):
            if item.get(key):
                item[key] = item[key].isoformat()
        try:
            item["posture"] = json.loads(item.get("posture_json") or "{}")
        except Exception:
            item["posture"] = {}
        return item

    def touch_device(self, device_id: str, tenant_id: str | None = None) -> None:
        tenant = tenant_id or self.tenant_id
        with self.engine.begin() as conn:
            conn.execute(
                update(device_enrollments)
                .where(device_enrollments.c.device_id == device_id, device_enrollments.c.tenant_id == tenant)
                .values(last_seen_at=datetime.now(timezone.utc))
            )

    def list_devices(self, user: str | None = None, limit: int = 100, tenant_id: str | None = None) -> list[dict[str, Any]]:
        tenant = tenant_id or self.tenant_id
        stmt = select(device_enrollments).where(device_enrollments.c.tenant_id == tenant)
        if user:
            stmt = stmt.where(device_enrollments.c.user == user)
        stmt = stmt.order_by(device_enrollments.c.last_seen_at.desc()).limit(min(int(limit or 100), 1000))
        with self.engine.begin() as conn:
            rows = conn.execute(stmt).mappings().all()
        results: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item.pop("device_token_hash", None)
            for key in ("enrolled_at", "last_seen_at"):
                if item.get(key):
                    item[key] = item[key].isoformat()
            try:
                item["posture"] = json.loads(item.get("posture_json") or "{}")
            except Exception:
                item["posture"] = {}
            item.pop("posture_json", None)
            results.append(item)
        return results

    def update_device_status(self, device_id: str, status: str, tenant_id: str | None = None) -> bool:
        tenant = tenant_id or self.tenant_id
        with self.engine.begin() as conn:
            result = conn.execute(
                update(device_enrollments)
                .where(device_enrollments.c.device_id == device_id, device_enrollments.c.tenant_id == tenant)
                .values(status=status, last_seen_at=datetime.now(timezone.utc))
            )
            return bool(result.rowcount)

    def users_summary(self, limit: int = 100, tenant_id: str | None = None) -> list[dict[str, Any]]:
        tenant = tenant_id or self.tenant_id
        stmt = (
            select(
                audit_events.c.user,
                func.count().label("events"),
                func.coalesce(func.sum(audit_events.c.estimated_cost_usd), 0.0).label("spend_usd"),
                func.max(audit_events.c.ts).label("last_seen_at"),
            )
            .where(audit_events.c.tenant_id == tenant)
            .group_by(audit_events.c.user)
            .order_by(func.count().desc())
            .limit(min(int(limit or 100), 1000))
        )
        with self.engine.begin() as conn:
            rows = conn.execute(stmt).mappings().all()
        return [
            {
                "user": row["user"],
                "events": int(row["events"] or 0),
                "spend_usd": float(row["spend_usd"] or 0.0),
                "last_seen_at": row["last_seen_at"].isoformat() if row.get("last_seen_at") else None,
            }
            for row in rows
        ]

    def model_usage(self, limit: int = 100, tenant_id: str | None = None) -> list[dict[str, Any]]:
        tenant = tenant_id or self.tenant_id
        stmt = (
            select(
                audit_events.c.model_used,
                func.count().label("events"),
                func.coalesce(func.sum(audit_events.c.input_tokens), 0).label("input_tokens"),
                func.coalesce(func.sum(audit_events.c.output_tokens), 0).label("output_tokens"),
                func.coalesce(func.sum(audit_events.c.estimated_cost_usd), 0.0).label("spend_usd"),
            )
            .where(audit_events.c.tenant_id == tenant, audit_events.c.model_used.is_not(None))
            .group_by(audit_events.c.model_used)
            .order_by(func.count().desc())
            .limit(min(int(limit or 100), 1000))
        )
        with self.engine.begin() as conn:
            rows = conn.execute(stmt).mappings().all()
        return [
            {
                "model": row["model_used"],
                "events": int(row["events"] or 0),
                "input_tokens": int(row["input_tokens"] or 0),
                "output_tokens": int(row["output_tokens"] or 0),
                "spend_usd": float(row["spend_usd"] or 0.0),
            }
            for row in rows
        ]

    def overview(self, since: str | datetime, tenant_id: str | None = None) -> dict[str, Any]:
        tenant = tenant_id or self.tenant_id
        if isinstance(since, str):
            since_dt = datetime.fromisoformat(since.replace("Z", "+00:00"))
        else:
            since_dt = since
        with self.engine.begin() as conn:
            events = int(conn.execute(select(func.count()).where(audit_events.c.tenant_id == tenant, audit_events.c.ts >= since_dt)).scalar() or 0)
            spend = float(conn.execute(select(func.coalesce(func.sum(audit_events.c.estimated_cost_usd), 0.0)).where(audit_events.c.tenant_id == tenant, audit_events.c.ts >= since_dt)).scalar() or 0.0)
            users = int(conn.execute(select(func.count(func.distinct(audit_events.c.user))).where(audit_events.c.tenant_id == tenant, audit_events.c.ts >= since_dt)).scalar() or 0)
            devices = int(conn.execute(select(func.count()).where(device_enrollments.c.tenant_id == tenant)).scalar() or 0)
        return {"events": events, "spend_usd": spend, "active_users": users, "devices": devices, "decision_counts": self.decision_counts_since(since_dt, tenant_id=tenant)}

