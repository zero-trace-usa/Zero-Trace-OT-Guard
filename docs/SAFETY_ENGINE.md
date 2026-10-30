# Safety policy and operator runbook

Version 1.0.0-rc.3 is an engineering release candidate for offline analysis and controlled lab evaluation. It is not production OT safety certification. The engine does not discover a safe rate for an unknown device. Even one handshake may disrupt fragile equipment.

## Offline first

Use `otguard analyze --input examples/sample --output reports` to analyze existing CSV evidence, or a supported capture, without contacting assets. Review inventory and findings with the asset owner. This release does not automatically translate passive findings into probe targets or determine device health.

## Signed connection policy

Start with `examples/approval.example.json`. All policy fields are covered by the existing HMAC signature. Provision `OTGUARD_APPROVAL_KEY` securely as described in SECURITY_HARDENING.md; do not commit secrets or live approvals.

| Field | Meaning and accepted range |
| --- | --- |
| `allowed_hosts` | Exact literal IP addresses; no DNS lookup or subnet expansion |
| `allowed_ports` | Explicit integer ports 1–65535; the built-in industrial port denylist still applies |
| `max_connections` | Total attempts per invocation, integer 1–100 |
| `min_delay_seconds` | Global minimum start-to-start spacing, 1–3600 seconds |
| `max_attempts_per_second` | Global maximum attempt rate, 1/3600–1; defaults to 1 |
| `per_host_cooldown_seconds` | Minimum start-to-start spacing for a host, 1–3600 seconds; defaults to minimum delay |
| `max_consecutive_failures` | Stop after this many consecutive unsuccessful connections, integer 1–100; defaults to 1 |
| `expires_utc` | Timezone-aware approval deadline; checked during waits and before each attempt |

The effective global spacing is the greater of minimum delay and the inverse rate. Host cooldown may increase it. Execution is serial with no retries, rate increases, or application payloads. Each socket timeout is at most one second and no greater than remaining approval validity. Earliest plan offsets assume instantaneous connections; actual attempts may occur later.

Limits apply to **one invocation**. They do not coordinate separate processes, users, machines, or repeated use of an approval. The approval is reusable until expiry. Operators must prevent parallel or repeated runs outside the authorized aggregate budget. The engine does not provide fleet-wide admission control or single-use authorization.

## Review and execute

1. Obtain the asset owner's written authorization and site-specific hazard assessment. Offline development does not authorize device contact.
2. Have the authorized approver populate and sign the approval using `otguard sign-approval --approval approval.json`.
3. Produce the offline plan:
   ```sh
   otguard active-check --approval approval.json --target 192.0.2.10 --port 443 --ack-authorized
   ```
4. Review the exact scope, timing, limits and `plan_id`. The plan ID binds the complete signed approval and canonical selected targets/ports. Changing either invalidates it. A matching identifier demonstrates consistency, not independent human review or identity.
5. In the approved controlled environment, use that identifier:
   ```sh
   otguard active-check --approval approval.json --target 192.0.2.10 --port 443 --ack-authorized --execute --plan-id REVIEWED_PLAN_ID --stop-file STOP --audit-file active-audit.jsonl
   ```
6. Inspect `active-results.json` and the audit log. `mode: interrupted` requires checking `stop_reason`; interrupted execution exits with status 3; invalid input or policy exits with status 2. A completed command does not establish device safety. `not_connected_or_filtered` does not distinguish refusal, timeout, routing failure, or filtering.

Existing signed approvals continue to validate with the documented defaults. To choose other limits, add the fields and re-sign. Execution from older scripts must add `--plan-id`; CLI execution writes an audit log by default, and API callers must explicitly provide one.

## Stopping and evidence

Create the configured stop file or press Ctrl+C to request a cooperative stop. Waiting checks the stop file and expiry approximately every 100 ms, subject to OS scheduling. An in-progress socket call may last up to its timeout. No software timing guarantee or safety-rated emergency stop is provided. The engine cannot retract packets already sent.

The JSONL audit records execution start with the full plan, intent before each connection, outcomes with monotonic offsets and duration, and a finish event with counts and stop reason. Each run has a random identifier. Writes are flushed and synchronized before connecting; audit write errors abort execution. A crash or disk error can leave an intent without a result or finish event: treat that attempt as potentially transmitted and reconcile externally before rerunning. Logging failure after a connection cannot undo that connection. Protect logs with OS permissions and centralized collection; they are not tamper-evident and contain network inventory.

Summary reasons include `plan_completed`, `operator_stop`, `operator_interrupt`, `approval_expired` and `consecutive_failure_limit`. Review the actual attempt count against the plan. Expired or invalid approvals and plan mismatches fail before network activity.

## Packet and safety limitations

These are connection-attempt budgets, not requests-per-second or packets-per-second guarantees. OS handshakes, retransmissions, teardown, routing/neighbor discovery and firewall behavior can generate additional packets. No kernel traffic shaper or packet-rate enforcement is included. Packet-level claims require separately configured network enforcement and capture-based validation.

A denylist is not proof that another port or host is safe. The engine does not measure PLC health, detect process disruption, validate vendor compatibility, or confirm vulnerabilities. HMAC requires a shared secret on the verifier, so it cannot distinguish a verifier holding the key from an authorized signer.

## Validation and release checklist

From the repository root after `python -m pip install -e '.[dev]'`:
```sh
python -m pytest -q
python -m compileall -q src
python -m bandit -q -r src -s B101
python -m pip check
python -m build
python -m otguard analyze --input examples/sample --output reports
```

The suite includes simulated timing, fail-closed policies, review binding, expiry and operator stop during waits, audit failure, a failure circuit breaker, and one loopback-only TCP server checking that no application payload is sent. A socket-capable test environment is required. No OT network or devices are used.

Before public release, require a green supported-version CI matrix, clean package installation and CLI smoke test, reviewed changes and accurate release notes. Hardware-in-the-loop safety testing, independent security review, parser fuzzing and site acceptance remain separate production gates. Do not advertise novelty or production readiness without evidence. This release does not claim those gates have passed.
