# Changelog

## 1.0.0-rc.3 — Reviewed safety plans
- Deterministic offline plans bound to the complete signed approval; execution requires the reviewed plan ID.
- Signed global connection-attempt rate, per-host cooldown and consecutive-failure budgets; serial execution only.
- Approval expiry checked during waits and before every attempt; socket timeout bounded by remaining validity.
- Durable pre-attempt audit records, run identifiers, timing evidence, explicit stop reasons and planned/actual counts.
- Fail-closed numeric policy validation, including NaN, infinity and boolean rejection.
- Local simulated-device coverage, operator runbook and Linux quick start.
- Breaking change: execution requires --plan-id and an audit destination. Legacy signed approvals retain conservative defaults for new limits.

## 1.0.0-rc.2 — Security hardening
- HMAC-SHA256 signed approval verification; signing CLI.
- Cooperative emergency-stop file and JSONL execution audit log.
- CSV formula neutralization and CSV/PCAP resource caps.
- Stronger PCAP IPv4 header, length, fragment, and VLAN validation.
- Added security regression tests and multi-version CI/static checks.
- Documented remaining OT safety and protocol-coverage limitations.

## 1.0.0-rc.1
Initial engineering candidate.
