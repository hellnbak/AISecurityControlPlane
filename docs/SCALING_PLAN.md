# AISecurityControlPlane 10k+ User Scaling Plan

## Control-plane vs enforcement-plane split

The scalable shape is not one giant synchronous proxy. It is:

- **Endpoint enforcement plane**: browser extension, local API proxy, optional TLS proxy, local policy cache, local DLP, local event buffer.
- **Central control plane**: policy bundles, budget counters, audit/event ingest, admin APIs, provider routing, reporting, SIEM export.

The endpoint should keep enforcing when the central control plane is temporarily unreachable.

## Added in this v0.3 build

- Postgres-ready audit store through `DATABASE_URL`.
- Redis-ready budget reservations through `REDIS_URL`.
- Async in-process audit queue with disk spillover.
- Signed policy bundle endpoint for endpoint agents/extensions.
- Event ingest endpoint for endpoint-buffered events.
- Hosted Claude.ai model rewrite/block responses from `/v1/web/evaluate`.
- Endpoint event-buffer demo.
- Docker Compose stack with Postgres + Redis + gateway.
- Kubernetes starter deployment and HPA.

## Production flow

```text
Endpoint extension/agent
  -> fast local policy cache decision
  -> local DLP scan
  -> optional local/TLS request rewrite
  -> local event buffer
  -> central /v1/control/events/ingest

Developer/API traffic
  -> local or regional AISecurityControlPlane /v1/messages
  -> Redis budget reserve
  -> provider call
  -> reconcile actual spend
  -> async audit event
```

## Recommended AWS deployment

- ECS/Fargate or EKS for stateless gateway/control-plane services.
- ALB for API ingress.
- RDS Postgres for policy/admin/current-state data.
- ElastiCache Redis for budget/rate/reservation counters.
- SQS/Kinesis/MSK for high-volume audit ingest in a later version.
- S3 partitioned audit data lake for long retention.
- Athena/QuickSight for executive reporting.
- OpenSearch or ClickHouse for fast investigation search.

## SLO targets

- Local policy decision: p95 < 50 ms.
- Remote policy decision: p95 < 150 ms.
- API proxy overhead excluding model latency: p95 < 250 ms.
- Audit ingestion lag: < 60 seconds.
- Policy bundle max age: 24 hours.
- Raw prompt logging: off by default.

## Next scale steps

1. Replace in-process audit queue with SQS/Kinesis/Kafka.
2. Add Alembic migrations instead of `metadata.create_all`.
3. Add JWT/OIDC validation for users and devices.
4. Add per-tenant encryption keys and KMS envelope encryption for evidence.
5. Add policy bundle verification in the endpoint extension/agent.
6. Add SIEM export workers.
7. Add fleet health dashboard.
8. Add provider rate-limit discovery and circuit breakers.
