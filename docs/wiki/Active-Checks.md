# Separate active TCP checks

Offline `analyze` never needs this workflow. Executing `active-check` performs TCP connection attempts and can affect fragile equipment. This engineering prerelease does not establish a safe rate or device-vendor compatibility.

## Prerequisites

Before executing against devices, obtain written asset-owner authorization and a site-specific hazard assessment. An authorized approver must define the exact scope, expiry and per-invocation budgets in a signed approval. Provision `OTGUARD_APPROVAL_KEY` securely on the signing/verifying systems; it must contain at least 32 characters. Do not place keys in documentation, commits, tickets or reports.

Start from `examples/approval.example.json`. Replace every operator, ticket and expiry placeholder and review all hosts, ports and budgets. Do not copy an example deadline as actual authorization. The shared HMAC key provides approval integrity, not independent human identity verification; a verifier holding that key can also create signatures.

## Sign and review an offline plan

The authorized approver signs the local approval file in place:

```sh
python -m otguard sign-approval --approval approval.json
```

In the operator's approved environment, produce a plan without executing connections:

```sh
python -m otguard active-check --approval approval.json --target 192.0.2.10 --port 443 --ack-authorized
```

The address above is documentation-only. Substitute only endpoints within the actual signed scope. Review `active-results.json`: selected targets/ports, connection count, spacing, expiry, budgets and `plan_id`. The acknowledgement flag is not itself authorization. The plan ID binds the signed approval and selected scope; it does not prove independent human review.

## Execute only in the separately approved controlled environment

This is an execution template, not a prerequisite for offline use:

```sh
python -m otguard active-check --approval approval.json --target 192.0.2.10 --port 443 --ack-authorized --execute --plan-id REVIEWED_PLAN_ID --stop-file STOP --audit-file active-audit.jsonl
```

Replace `REVIEWED_PLAN_ID` with the identifier from the reviewed plan. The example is deliberately incomplete. Existing stop requests must be investigated and resolved through the approved procedure; do not blindly delete a STOP file to make execution proceed. Create STOP or press Ctrl+C to request a cooperative stop. An in-progress socket call may continue until its timeout; transmitted packets cannot be retracted.

## What the controls enforce

- Exact literal approved IP addresses and ports; no DNS or subnet expansion.
- Serial TCP connects with no OT protocol payload, credential tests or exploitation.
- Connection-attempt count, global spacing, per-host cooldown, expiry and consecutive-failure cutoff.
- Reviewed plan binding and durable audit intent before each attempt.

Ports 102, 502, 2222, 2404, 4840, 20000, 44818 and 47808 remain denied. A different port is not evidence of device safety. These are per-invocation connection budgets, not packet-rate guarantees or aggregate limits across processes/operators. Approvals remain reusable until expiry; the engine does not coordinate concurrent executions.

## Review results

Check `mode`, `stop_reason`, attempt counts, outcomes and the JSONL audit. `not_connected_or_filtered` does not distinguish refusal, timeout, routing or filtering. Exit 3 means interrupted execution; exit 2 means an argument/input/policy or related error. An audit error after an attempt cannot undo it; an unmatched intent may indicate traffic was sent. Logs are not tamper-evident.

The full accepted policy ranges and operational limitations are in the [operator runbook](https://github.com/zero-trace-usa/Zero-Trace-OT-Guard/blob/main/docs/SAFETY_ENGINE.md) and [signing instructions](https://github.com/zero-trace-usa/Zero-Trace-OT-Guard/blob/main/docs/SECURITY_HARDENING.md).

Return to [offline workflows](Home.md).
