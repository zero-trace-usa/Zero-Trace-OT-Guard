# Changelog

## 1.0.0-rc.6 — Offline Modbus write analysis
- Added optional TShark dissection of Modbus/TCP write requests with an explicit source and optional destination allowlist.
- Added frame/PDU evidence, authorized and unexpected write records, CSV/HTML/JSON output and visible coverage limits.
- Explicitly require MBAP protocol identifier zero, including on TShark versions that decode non-Modbus identifiers as Modbus-shaped commands.
- Added actual-dissector regression captures and CI TShark installation; existing CSV and metadata-only workflows remain available.
- Engineering prerelease for offline analysis and controlled lab evaluation; not production safety certification.

## 1.0.0-rc.5 — Zero-Trace branding
- Added the approved Zero-Trace OT Guard wordmark, transparent logo and square profile avatar.
- Branded the README, release notes and standalone HTML reports with packaged assets.
- Embedded report logos and favicon locally, with no external image requests.
- Added brand asset guidance and installed-package coverage.

## 1.0.0-rc.4 — Installation and documentation consistency
- Standardized product, distribution, command and version naming.
- Added CLI --version and option/default help, plus a complete commands/settings reference.
- Replaced developer-only quick start with version-pinned user installation instructions.
- Corrected stale unsigned-approval and CSV-export claims in architecture/safety documentation.
- Added package README/URLs and included documentation and examples in source distributions.
- Removed a fixed sample approval deadline; operators must explicitly choose their authorized expiry.
- Updated release workflow actions to Node 24 versions.

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
