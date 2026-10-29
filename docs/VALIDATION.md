# Validation and Release Gates

## Included automated tests
Unit tests cover zone conflicts, advisory matches, HTML escaping, classic PCAP metadata parsing, approval acknowledgement, scope enforcement, industrial-port rejection and network-free dry runs.

## Required before production
- Independent security review and threat modeling; fuzz malformed captures and CSVs.
- Hardware-in-the-loop tests across actual target devices and representative network conditions.
- Benchmark processing memory/time and investigate packet drops and capture completeness.
- Verify no unexpected packets in passive mode using an external capture.
- Validate active traffic and failure handling using a network tap and packet capture.
- Formal site safety risk assessment, change approval, rollback and incident plan.
- Review standards applicability (e.g. IEC 62443), and pursue independent conformity assessment if desired.

No external certification, accredited testing, hardware-in-the-loop validation, or plant acceptance has been performed by this release process.
