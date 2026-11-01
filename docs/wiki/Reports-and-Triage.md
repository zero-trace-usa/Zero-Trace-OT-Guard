# Reports and triage

## Output files

| File | What it contains |
| --- | --- |
| `report.html` | Standalone review report with embedded branding and escaped table content |
| `report.json` | Structured summary, assets, flows, findings, limitations and evidence metadata |
| `assets.csv` | Provided inventory plus observed addresses absent from that inventory |
| `flows.csv` | Normalized TCP/UDP flow metadata and indicative service labels |
| `findings.csv` | Zone conflicts, inventory advisory matches and unexpected write findings |
| `write_operations.csv` | Additional file when write analysis is enabled; includes authorized and unexpected requests |

Use a new directory for each run. A failed run does not remove earlier files from a reused directory. CSV formula prefixes are neutralized, but exports remain untrusted data and may contain sensitive network inventory.

## Summary interpretation

`observed_assets` is the size of the merged asset inventory; it can include operator-supplied inventory entries not observed in the selected traffic. `flows` counts normalized flow records. `findings` counts review indicators, including unexpected writes when enabled. None is a count of confirmed vulnerabilities or successful device operations.

## Finding types

| Finding | What the evidence establishes | What to check next |
| --- | --- | --- |
| Observed zone policy conflict | A flow matches a supplied deny rule and inventory zones | Inventory accuracy, approved conduits, firewall logs and exceptions |
| Potential advisory match | Supplied vendor/product and optional exact version match inventory | Actual firmware, vendor guidance, affected ranges and compensating controls |
| Unexpected Modbus write request | A supported decoded request does not match the source/destination allowlist | Source ownership, approved maintenance, destination scope and original capture |

Current findings use severity `Review`. The tool does not calculate exploitability, CVSS, confidence probabilities or production safety certification.

## Write-analysis coverage

When enabled, JSON includes `write_operations` and `write_analysis`. HTML includes write-request and coverage tables. Important coverage fields include:

| Field | Interpretation |
| --- | --- |
| `evaluated_allowlist` | Normalized rules actually used for this run |
| `write_requests` | Supported decoded requests retained for authorization review |
| `decoded_modbus_pdus` | PDUs counted after frame-level protocol/context checks; includes replies and requests |
| `other_or_unassessed_requests` | Candidate request PDUs outside supported write coverage or lacking endpoints |
| `ambiguous_direction_pdus` | PDUs whose configured ports do not establish a unique direction |
| `unassessed_protocol_frames` | Missing, nonzero or mixed MBAP protocol identifier contexts |
| `unassessed_context_frames` | Frames with multiple IP/TCP layers that cannot be attributed safely |
| `malformed_frames` | Malformed frames returned by the Modbus display filter |
| `packet_limit`, `decode_as_tcp_ports`, `warnings` | Run settings and dissector diagnostics |

These counters are not a complete accounting of all packets. Filtering and exclusions occur at different stages. Read JSON `evidence_metadata` as well: ordinary PCAP parsing warnings are not all shown in the basic HTML report.

## A practical review sequence

1. Record the software version, evidence provenance and exact run command.
2. Check metadata warnings, packet limits and unassessed contexts before interpreting absence of findings.
3. Validate inventory zones, advisory inputs and the evaluated write allowlist.
4. Review unexpected writes in the original capture using the frame and PDU references.
5. Confirm expected maintenance, endpoint ownership and capture placement with the asset owner.
6. Record the disposition and supporting evidence outside the generated report. Preserve the original report before rerunning.

Do not automatically convert a finding into an active probe or a blocking firewall change. Those require separate operational review.

Next: [troubleshooting](Troubleshooting.md) or [security and evidence handling](Security-and-Data-Handling.md).
