# v1.0.0-rc.5 security hardening

Commands assume an activated virtual environment; see the [installation guide](../README.md). Offline analysis needs no signing key.

## Approval integrity
Active checks now require an HMAC-SHA256 signature on the JSON approval file, using a separately provisioned `OTGUARD_APPROVAL_KEY` of at least 32 characters. The approver should hold the signing key separately from the operator. **This is shared-secret integrity, not independent identity verification or PKI-based authorization.** A compromised signing key can authorize arbitrary approvals. Do not commit approval secrets or live approval files.

### Approver (isolated trusted environment)
1. Generate a random key using a trusted password manager or secrets system; provision it through a secure channel.
2. Set the environment variable `OTGUARD_APPROVAL_KEY` locally. Never paste the secret into a ticket or commit it.
3. Fill out an approval JSON from `examples/approval.example.json`, using the approved operator, ticket, expiry, exact hosts and ports.
4. Run `python -m otguard sign-approval --approval approval.json`.
5. Transfer the signed approval to the operator via an approved process.

### Operator
1. Provision the verification key securely. Confirm the signed approval is within scope.
2. Run a dry-run before any execution:
   `python -m otguard active-check --approval approval.json --target 192.0.2.10 --port 443 --ack-authorized`
3. Only with additional operational approval, run `--execute --plan-id <reviewed-plan-id> --stop-file STOP --audit-file active-audit.jsonl`.
4. To request stop, create the file `STOP` in the operator working directory. Remove stale STOP files before execution. Ctrl+C also interrupts the process. Stop is cooperative; an in-progress socket call may take up to one second to return.

## Scope and limitations
- TCP connect only; no industrial protocol commands, firmware reads, or exploitation.
- Default is dry-run. Acknowledgement, valid signed approval, explicit `--execute`, and exact IP/port scope are required.
- Denied OT ports remain blocked. A connect to an allowed port is still active network traffic and may affect fragile equipment.
- Audit log is append-only at application level, **not tamper-evident**. Protect it using external centralized logging and access controls.
- PCAP is limited to classic Ethernet IPv4 TCP/UDP metadata. IPv6, PCAPNG and protocol payload decoding are unsupported. Malformed records may be skipped; inspect warnings and incomplete-capture indicators.
- Advisory matching is exact inventory-field correlation, **not** a verified affected-version range engine. Treat findings as potential matches.
- CSV inputs are limited to 20 MiB/100,000 rows; PCAP to 256 MiB and at most 1,000,000 processed packets.

## Production release gates
Hardware-in-the-loop safety testing, independent security assessment, threat modeling, protocol parser fuzzing, deployment runbooks, operator training, and acceptance by the OT asset owner are **not complete**. Do not call this release production-certified.

See [Safety policy and operator runbook](SAFETY_ENGINE.md) for connection budgeting and audit behavior.
