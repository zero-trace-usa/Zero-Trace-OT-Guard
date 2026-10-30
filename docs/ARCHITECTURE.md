# Architecture

1. **Offline ingestion:** `flows.csv` or classic Ethernet/IPv4 `capture.pcap`.
2. **Normalization:** validate IPs, TCP/UDP ports and counters; assign indicative service label based on destination port.
3. **Asset inventory:** merge provided `assets.csv` with observed addresses; unknown zone where not supplied.
4. **Correlation:** compare observed flows to `rules.csv`; match supplied `advisories.csv` to vendor/product/version metadata. No online vulnerability feed is bundled.
5. **Reporting:** escaped standalone HTML, JSON and CSV.
6. **Separate active command:** HMAC policy verification, deterministic offline plan, reviewed plan identifier, explicit acknowledgement; optional serial TCP connects with signed timing/failure budgets, expiry checks and durable audit records. No OT application payload.

## Trust boundaries
Imported CSV/PCAP and approval files are untrusted local inputs. The HTML renderer escapes fields. Approval files use HMAC-SHA256 shared-key integrity. Execution is bound to the reviewed plan ID and signed per-invocation budgets. Exported CSV formula prefixes are neutralized; still treat imported data as untrusted and follow spreadsheet security guidance. PCAP parser is minimal and should be fuzz-tested before processing hostile captures.

## Out of scope
Deep packet inspection, protocol command decoding, IPv6, PCAPNG, automated vulnerability verification, credentialed checks, independent approval identity verification, SIEM integration, multiuser UI, continuous capture, and high-availability deployment.
