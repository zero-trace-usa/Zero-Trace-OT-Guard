> **Engineering candidate v1.0.0-rc.2 — not production-certified.** Active checks transmit TCP traffic and require separately authorized execution. See [Security Hardening](docs/SECURITY_HARDENING.md) and [Safety](docs/SAFETY.md).

# Zero-Trace OT Guard — v1.0 Enterprise (Engineering Candidate)

**Passive-first OT evidence analyzer with optional, separately authorized TCP connectivity checks.**

> **Not certified or independently validated for production OT use.** The “Enterprise” label identifies the intended project edition, not an independent assurance level. Test in an isolated lab and complete site-specific safety review before deployment.

## Features
- Offline classic Ethernet/IPv4 PCAP metadata extraction (TCP/UDP), or CSV flow import.
- Asset inventory merging, indicative port-based industrial service labels, zone/conduit policy conflict review.
- Offline advisory-to-inventory matching (**potential matches, never confirmed vulnerabilities**).
- HTML, JSON, and CSV outputs with HTML escaping.
- Active mode is **off by default**. The separate command requires a scoped, expiring approval JSON, an explicit acknowledgement, and `--execute` to connect.
- Active checks perform **TCP connect only**, no protocol commands, no credential testing, no exploitation, and refuse industrial protocol ports.

## Windows Quick Start (Python 3.10+)
```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m otguard analyze --input examples/sample --output reports
Start-Process .\reports\report.html
.\.venv\Scripts\python.exe -m pytest -q
```

## PCAP import
Put a classic PCAP file named `capture.pcap` in a folder, then run `otguard analyze --input <folder> --output reports`. CSV `flows.csv` takes precedence. PCAPNG, IPv6, fragments, nested VLANs, non-Ethernet captures, and protocol payload decoding are **not supported**. The parser retains metadata only; PCAP flow bytes are reported as zero because byte accounting is not implemented. Packet processing is capped by `--max-packets` (default 500,000).

## Active connectivity workflow
1. Obtain a signed change ticket and documented written authorization from the asset owner; complete an OT hazard assessment.
2. Create a local approval JSON based on `examples/approval.example.json`, with exact IPs, ports, expiry, budget and delay. **The JSON is an operator-supplied control, not a cryptographically authenticated authorization system.**
3. Review the dry run:
```powershell
otguard active-check --approval approval.json --target 192.0.2.10 --port 443 --ack-authorized
```
4. Only after out-of-band approval and in a controlled environment, add `--execute`. The command writes `active-results.json` locally.

**Never use active checks on PLCs, safety controllers, or production industrial devices without site-specific authorization and engineering approval.** Even a TCP handshake can affect fragile equipment. No claim of zero impact is made.

## GitHub upload
Create `zero-trace-usa/Zero-Trace-OT-Guard` without initial files; extract this ZIP and upload its contents including `.github/workflows/tests.yml`. Or use Git: `git init; git add .; git commit -m "Initial engineering candidate"; git branch -M main; git remote add origin https://github.com/zero-trace-usa/Zero-Trace-OT-Guard.git; git push -u origin main`.

## Important limitations
This is a functioning reference implementation, **not** a comprehensive industrial protocol decoder, full vulnerability scanner, certified product, or production-ready deployment. See `docs/SAFETY.md`, `docs/ARCHITECTURE.md`, and `docs/VALIDATION.md`.

## v1.0.0-rc.2 safety controls

Active connectivity checks require explicit authorization and an HMAC-verified approval file. The scanner also provides scope restrictions, cooperative emergency-stop functionality, and structured audit logging. These controls are intended to reduce operational risk but do not establish production OT safety certification. Refer to `docs/SECURITY_HARDENING.md` for configuration requirements and limitations.
