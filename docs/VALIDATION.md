# Validation status — v1.0.0-rc.2

- 11 unit/regression tests passed in local source environment (Python 3.13).
- GitHub Actions is configured to test Python 3.11, 3.12 and 3.13, compile source, and run Bandit. CI results must be verified after push.
- No hardware-in-the-loop validation, device-vendor compatibility certification, or independent penetration test has been performed.
- The PCAP parser is metadata-only; vulnerability correlation is inventory-based, not verified exploitability.
- Signed approval relies on key custody. The stop-file is cooperative, not a safety-rated emergency-stop system.
