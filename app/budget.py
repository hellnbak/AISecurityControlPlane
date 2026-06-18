from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .store import AuditStore

try:
    import redis  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    redis = None


class BudgetService:
    """Budget checks with Redis reservation support and store-backed fallback."""

    def __init__(self, *, store: AuditStore, redis_url: str = "", tenant_id: str = "demo-org"):
        self.store = store
        self.redis_url = redis_url
        self.tenant_id = tenant_id
        self.client = None
        if redis_url and redis is not None:
            try:
                self.client = redis.Redis.from_url(redis_url, decode_responses=True)
                self.client.ping()
            except Exception:
                self.client = None

    @property
    def mode(self) -> str:
        return "redis" if self.client else "store-fallback"

    def _period_keys(self, user: str) -> tuple[str, str, str, str]:
        now = datetime.now(timezone.utc)
        day = now.strftime("%Y%m%d")
        month = now.strftime("%Y%m")
        prefix = f"secureai:{self.tenant_id}:budget:{user}"
        return (
            f"{prefix}:day:{day}:actual",
            f"{prefix}:day:{day}:reserved",
            f"{prefix}:month:{month}:actual",
            f"{prefix}:month:{month}:reserved",
        )

    def spend_snapshot(self, user: str, day_start_iso: str, month_start_iso: str) -> dict[str, Any]:
        if not self.client:
            return {
                "mode": self.mode,
                "daily_actual_usd": self.store.spend_since(user, day_start_iso, tenant_id=self.tenant_id),
                "daily_reserved_usd": 0.0,
                "monthly_actual_usd": self.store.spend_since(user, month_start_iso, tenant_id=self.tenant_id),
                "monthly_reserved_usd": 0.0,
            }
        day_actual, day_reserved, month_actual, month_reserved = self._period_keys(user)
        vals = self.client.mget(day_actual, day_reserved, month_actual, month_reserved)
        return {
            "mode": self.mode,
            "daily_actual_usd": float(vals[0] or 0),
            "daily_reserved_usd": float(vals[1] or 0),
            "monthly_actual_usd": float(vals[2] or 0),
            "monthly_reserved_usd": float(vals[3] or 0),
        }

    def reserve(self, user: str, amount_usd: float, *, daily_budget: float, monthly_budget: float, day_start_iso: str, month_start_iso: str) -> dict[str, Any]:
        amount = max(float(amount_usd or 0), 0.0)
        snapshot = self.spend_snapshot(user, day_start_iso, month_start_iso)
        projected_day = snapshot["daily_actual_usd"] + snapshot["daily_reserved_usd"] + amount
        projected_month = snapshot["monthly_actual_usd"] + snapshot["monthly_reserved_usd"] + amount
        allowed = projected_day <= daily_budget and projected_month <= monthly_budget
        reservation_id = f"res-{datetime.now(timezone.utc).timestamp()}"
        if allowed and self.client and amount > 0:
            _day_actual, day_reserved, _month_actual, month_reserved = self._period_keys(user)
            pipe = self.client.pipeline()
            pipe.incrbyfloat(day_reserved, amount)
            pipe.expire(day_reserved, 60 * 60 * 48)
            pipe.incrbyfloat(month_reserved, amount)
            pipe.expire(month_reserved, 60 * 60 * 24 * 45)
            pipe.execute()
        return {
            "allowed": allowed,
            "reservation_id": reservation_id,
            "reserved_usd": amount if allowed else 0.0,
            "snapshot": snapshot,
            "projected_daily_usd": projected_day,
            "projected_monthly_usd": projected_month,
        }

    def reconcile(self, user: str, reserved_usd: float, actual_usd: float) -> None:
        if not self.client:
            return
        amount_reserved = max(float(reserved_usd or 0), 0.0)
        amount_actual = max(float(actual_usd or 0), 0.0)
        day_actual, day_reserved, month_actual, month_reserved = self._period_keys(user)
        pipe = self.client.pipeline()
        if amount_reserved:
            pipe.incrbyfloat(day_reserved, -amount_reserved)
            pipe.incrbyfloat(month_reserved, -amount_reserved)
        if amount_actual:
            pipe.incrbyfloat(day_actual, amount_actual)
            pipe.expire(day_actual, 60 * 60 * 48)
            pipe.incrbyfloat(month_actual, amount_actual)
            pipe.expire(month_actual, 60 * 60 * 24 * 45)
        pipe.execute()
