# Troubleshooting

Start with the installed version and relevant `--help` output. Use a fresh output directory when retrying so old reports cannot be mistaken for new results.

| Symptom | Likely cause and correction |
| --- | --- |
| `No module named otguard` | Use the same virtual-environment Python for installation and execution; reinstall the matching source if necessary |
| `otguard` command not found | Activate the environment or use `python -m otguard` with its explicit Python path |
| venv creation unavailable | Install your OS's Python venv support; do not install the application into an unrelated system interpreter |
| TShark required / executable missing | Install TShark and ensure `tshark --version` works in the terminal running OT Guard |
| Expected flows.csv or capture.pcap | Check directory, exact filenames and source-archive examples; a wheel does not supply example input folders |
| --write-policy requires capture.pcap without flows.csv | Separate capture evidence from flow CSV exports, or omit write analysis when doing CSV-only review |
| Unsupported capture format or link type | Provide classic Ethernet/IPv4 PCAP; changing a filename extension does not convert the capture |
| Input or packet limit reached | Inspect warnings and assess incomplete coverage; use a justified supported limit or bounded evidence subsets |
| TShark failed or exceeded 120 seconds | Review diagnostics, capture validity, tool version and capture size; a failed analysis is not a clean result |
| Reports appear unchanged after failure | Previous output files remain; use a new output directory and verify the command completed |
| No write findings | Check whether writes were decoded, all were allowed, traffic is encrypted/unsupported, direction is ambiguous, or the capture is incomplete |
| Unexpected write from a known workstation | Check its exact observed source, destination scope, NAT/capture placement and approved maintenance; do not broaden the allowlist merely to suppress a finding |
| Signature, expiry or plan mismatch | Review approval scope, secure key provisioning and reviewed plan; re-sign only through the authorized approver |
| Active execution interrupted | Inspect stop_reason and the audit before considering a separately authorized rerun |

## Inspect a capture offline

This diagnostic command reads the existing file and disables name resolution:

```sh
tshark -n -r evidence/capture.pcap -Y mbtcp -T fields -e frame.number -e mbtcp.prot_id -e modbus.func_code
```

For a known nonstandard server port, add `-o mbtcp.tcp.port:502,1502`. A flattened diagnostic row can include multiple decoded messages; use the original packet details and OT Guard's frame/PDU records for attribution. A visible function field alone is insufficient: the MBAP identifier must be zero, direction must be clear and the function must be supported.

Check JSON `evidence_metadata` and `write_analysis` for exclusions. Basic port-based service labels and inventory matches do not establish command coverage. No decoded Modbus writes may be the correct outcome for a capture containing only other protocols.

## Request help

Report the tool/Python/TShark versions, exact sanitized command, exit status and relevant diagnostics. Include a minimal synthetic or approved-redacted reproduction when possible. Do not attach live approvals, keys, unredacted OT captures or identifying network inventories to public issues. See the repository's [security policy](https://github.com/zero-trace-usa/Zero-Trace-OT-Guard/blob/main/SECURITY.md).
