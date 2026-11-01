# Zero-Trace OT Guard user guide

Zero-Trace OT Guard analyzes existing OT network evidence and produces reviewable HTML, JSON and CSV reports. This guide covers **v1.0.0-rc.6**, an engineering prerelease for offline analysis and controlled lab evaluation. Production OT safety and device-vendor compatibility have not been certified.

## Choose your workflow

| Your objective | Required inputs and tools | Start here |
| --- | --- | --- |
| Review flows, zones and inventory advisory matches | Python 3.10+; `flows.csv` and optional inventory/rules/advisories | [Quick start](Quick-Start.md) |
| Review captured TCP/UDP flow metadata | Python 3.10+; classic Ethernet/IPv4 `capture.pcap` | [Prepare evidence](Evidence-Preparation.md) |
| Flag unexpected Modbus write requests | The supported PCAP; TShark on PATH; an explicit JSON write allowlist | [Modbus write detection](Write-Detection.md) |
| Review an authorized TCP-connect plan | A signed approval and securely provisioned signing/verification key | [Separate active checks](Active-Checks.md) |
| Execute TCP connectivity checks | Additional asset-owner authorization, hazard assessment and reviewed plan; controlled environment | [Separate active checks](Active-Checks.md) |

**Offline analysis requires no API key, background service or device connection.** The optional active command is a separate operation that sends network traffic when explicitly executed.

## Read in order

1. [Install and verify the tool](Installation.md).
2. [Run the bundled sample](Quick-Start.md).
3. [Prepare your evidence](Evidence-Preparation.md).
4. [Configure Modbus write authorization](Write-Detection.md), if needed.
5. [Interpret and triage reports](Reports-and-Triage.md).
6. [Resolve problems](Troubleshooting.md) and consult the [command reference](Command-Reference.md).

See [security and evidence handling](Security-and-Data-Handling.md) before sharing captures or reports, and [development and Wiki maintenance](Development-and-Wiki-Maintenance.md) for contributors.

## Understand the result

Findings are review indicators. Port-based service labels do not establish an industrial operation. Optional Modbus write findings require decoded function fields and MBAP protocol identifier zero, with configured server ports establishing request direction. A captured write request does not prove the device performed the write. No findings does not prove that no unsafe operations occurred.

[Repository](https://github.com/zero-trace-usa/Zero-Trace-OT-Guard) · [Release downloads](https://github.com/zero-trace-usa/Zero-Trace-OT-Guard/releases/tag/v1.0.0-rc.6) · [Validation evidence](https://github.com/zero-trace-usa/Zero-Trace-OT-Guard/blob/main/docs/VALIDATION.md)
