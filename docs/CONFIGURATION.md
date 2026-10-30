# Commands and settings

These commands assume an activated virtual environment. You can instead use `.venv/bin/python -m otguard` on Linux/macOS or `.\.venv\Scripts\python.exe -m otguard` in Windows PowerShell. The product is Zero-Trace OT Guard; the command and module are `otguard`.

## General

`python -m otguard --version` prints the product and installed Python package version. `--help` on the main command or any subcommand lists its options. Paths are relative to the current working directory unless absolute. Quote paths with spaces. Parent directories for active result and audit files must already exist.

There is no global settings file, network listener, account registration or telemetry configuration. Offline analysis requires no environment variables. Active approval verification and signing read only `OTGUARD_APPROVAL_KEY`, a securely provisioned shared secret of at least 32 characters. Never commit or include its value in logs. Proxy-backed API placeholders are not a substitute for the local HMAC key.

## Offline analysis

| Option | Requirement/default | Effect |
| --- | --- | --- |
| `--input DIRECTORY` | Required | Read flows.csv or capture.pcap; CSV takes precedence |
| `--output DIRECTORY` | `reports` | Create the directory; overwrite report.html, report.json, assets.csv, flows.csv and findings.csv |
| `--max-packets INTEGER` | `500000` | PCAP processing cap, 1–1000000; unused with CSV |

Optional files in the input directory: assets.csv, advisories.csv and rules.csv. Copy column names from examples/sample. CSV files are capped at 20 MiB and 100,000 rows each; PCAP at 256 MiB. Offline flow CSV accepts literal IPv4 or IPv6 addresses and TCP/UDP flows; the PCAP decoder supports IPv4 only. PCAP limitations are described in the README. Outputs can contain sensitive inventory; store them with appropriate filesystem permissions.

## Approval signing

`python -m otguard sign-approval --approval approval.json` signs the file **in place** using OTGUARD_APPROVAL_KEY. This does not check whether the supplied policy is operationally approved or safe. The active-check command verifies the signature and policy before creating a plan or connecting. See SECURITY_HARDENING.md for the approver/operator separation and shared-key limitations.

The example approval intentionally contains operator, ticket and expiry placeholders. Replace them before signing; the expiry must include a timezone, for example `2027-01-01T00:00:00Z` only if that is your actually approved future deadline. Do not copy a sample deadline as authorization.

## Active checks and offline plans

| Option | Requirement/default | Effect |
| --- | --- | --- |
| `--approval FILE` | Required | Read signed scope and policy |
| `--target IP` | Required; repeatable | Exact literal approved IP; no subnet expansion or DNS |
| `--port INTEGER` | Required; repeatable | Approved TCP port; industrial denylist remains enforced |
| `--ack-authorized` | Required acknowledgement | Does not itself grant authorization |
| `--execute` | Off | If omitted, create an offline plan without sockets or execution audit writes |
| `--plan-id IDENTIFIER` | Required for execution | Must match the plan for the current signed approval and selected scope |
| `--output FILE` | `active-results.json` | Overwrite JSON plan/result; JSON is also printed to stdout |
| `--stop-file FILE` | None | Existing file requests cooperative stop during execution; inspect rather than blindly deleting stale stops |
| `--audit-file FILE` | `active-audit.jsonl` | Append execution events; failure aborts execution |

All combinations of selected unique targets and ports are planned. Duplicates are removed. An IPv6 target requires an explicitly approved literal IPv6 address and a compatible local network; that does not imply IPv6 capture decoding support. The engine does not coordinate other running instances or prevent reuse of a still-valid approval.

Approval fields, numeric ranges, defaults and hard limits are documented in the [signed connection policy table](SAFETY_ENGINE.md#signed-connection-policy). The built-in denied ports are 102, 502, 2222, 2404, 4840, 20000, 44818 and 47808. Allowed ports are not evidence that a host is safe. One attempt is not one packet; the OS controls TCP behavior.

The stop file is cooperative and cannot cancel already transmitted traffic. Start-to-start spacing may exceed the planned minimum due to connection duration or OS scheduling. A socket timeout is at most one second. See the operator runbook for audit interpretation and partial attempts.

## Exit status

| Status | Meaning |
| --- | --- |
| `0` | Command completed, including an offline plan; connection outcomes still need review |
| `2` | Argument, input, signature, policy or filesystem error |
| `3` | Execution interrupted by operator, approval expiry or consecutive-failure cutoff |

An audit or output-write failure can occur after an attempt. A failed command is not evidence that no traffic was sent; reconcile audit intent records before another run. Stop requests and signed approvals are software controls, not safety-rated protection.
