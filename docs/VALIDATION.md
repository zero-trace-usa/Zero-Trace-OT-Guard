# Validation status — v1.0.0-rc.3

Validated locally on Python 3.12:

- 36 unit, regression and loopback integration tests passed, including offline parsing/reporting, policy rejection, deterministic plans, global and host timing, approval expiry, stop requests, interrupt accounting, audit failure, CLI behavior and a TCP handshake with no application payload.
- Source compilation and Bandit passed (B101 excluded, matching repository CI).
- Source distribution and wheel built successfully. A clean virtual environment installed the wheel without dependencies, loaded version 1.0.0rc3 and ran the offline sample through the installed CLI.
- The sample produced HTML/JSON/CSV reports with 3 assets, 2 flows and 2 findings.

GitHub Actions is configured for Python 3.10, 3.11, 3.12 and 3.13, tests, compilation, Bandit, builds and installed-wheel smoke checks. Remote CI results and other platform behavior have not been verified in this environment. No release has been published by this validation.

No hardware-in-the-loop validation, device-vendor compatibility certification, packet-rate enforcement validation, parser fuzz campaign or independent security assessment has been performed. Connection limits are per invocation, not aggregate across operators or processes. Audit logging is not tamper-evident. A matching plan identifier is not evidence of independent human review.

The PCAP parser retains supported metadata only. Advisory correlation is inventory-based and does not verify exploitability. Shared-key approval signing relies on key custody; the stop file is cooperative, not a safety-rated emergency-stop system. See SAFETY_ENGINE.md and SECURITY_HARDENING.md for operating constraints and production gates.
