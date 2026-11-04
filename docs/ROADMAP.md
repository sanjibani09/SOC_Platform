# Remaining work against the supplied build guide

- Implement TOTP enrolment/verification and require MFA before issuing the full JWT.
- Validate JWTs during the WebSocket handshake and authorize subscriptions by role.
- Move alert fan-out to a Redis pub/sub listener so multiple backend replicas share alerts.
- Load enabled detection rules and JSONB thresholds dynamically instead of using demo constants.
- Add transition validation for New → Acknowledged → Investigating → Resolved and false-positive closure.
- Expand audit coverage to authentication, MFA, assignments, rule changes and user management; make audit access insert-only.
- Add assignment workflow, related-event pivots, MITRE detail links and suggested labels for ML-only detections.
- Add Testcontainers integration tests, rule/scoring unit tests, ML precision/recall evaluation and seeded historical chart data.
- Add frontend production hardening, secure token storage, pagination, input validation, accessible states and automated tests.
