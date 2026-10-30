# Validation status — v1.0.0-rc.4

Validated locally on Python 3.12:

- 38 unit, regression and loopback integration tests passed, including offline parsing/reporting, policy rejection, deterministic plans, global and host timing, approval expiry, stop requests, interrupt accounting, audit failure, CLI behavior and a TCP handshake with no application payload.
- Source compilation and Bandit passed (B101 excluded, matching repository CI).
- Source distribution and wheel built successfully. A clean virtual environment installed the wheel without dependencies, loaded version 1.0.0rc4 and ran the offline sample through the installed CLI.
- The sample produced HTML/JSON/CSV reports with 3 assets, 2 flows and 2 findings.

GitHub Actions is configured for Python 3.10, 3.11, 3.12 and 3.13, tests, compilation, Bandit, builds and installed-wheel smoke checks. The preceding rc.3 release passed its public Python 3.10–3.13 CI matrix and publication workflow; its public package checksums and installed-wheel sample were verified. The rc.4 update must pass its own tagged workflow before publication. Windows and macOS behavior has not been validated in CI.

No hardware-in-the-loop validation, device-vendor compatibility certification, packet-rate enforcement validation, parser fuzz campaign or independent security assessment has been performed. Connection limits are per invocation, not aggregate across operators or processes. Audit logging is not tamper-evident. A matching plan identifier is not evidence of independent human review.

The PCAP parser retains supported metadata only. Advisory correlation is inventory-based and does not verify exploitability. Shared-key approval signing relies on key custody; the stop file is cooperative, not a safety-rated emergency-stop system. See SAFETY_ENGINE.md and SECURITY_HARDENING.md for operating constraints and production gates.

The rc.4 packaging audit also checks that the source distribution includes examples and documentation, and that CLI version output matches the package version.
