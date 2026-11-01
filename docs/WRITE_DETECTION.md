# Offline Modbus write detection

This optional analysis uses the installed TShark command to decode captured Modbus/TCP messages. Python applies an explicit allowlist and produces reports; it does not implement another industrial packet decoder. No live capture, name resolution, or device requests are performed. Existing CSV and metadata-only PCAP analysis remain available without TShark.

## Run

Install TShark using your operating system's supported package manager (for example, `sudo apt-get install tshark` on Debian/Ubuntu). Live-capture privileges are unnecessary. TShark must be on PATH. Integration tests were validated with TShark 4.4.18 and 4.0.17 on Linux; keep the dissector updated when processing untrusted captures.

Create an input directory containing `capture.pcap`, without `flows.csv`. The current CLI still requires classic Ethernet/IPv4 PCAP for its flow reader; this feature does not add PCAPNG or IPv6 capture support. Copy and review `examples/write-policy.example.json`, replacing documentation addresses with the approved endpoints:

```sh
python -m otguard analyze --input evidence --output reports --write-policy write-policy.json
```

For Modbus on a known nonstandard server port, explicitly add `--modbus-tcp-port 1502`. Repeat the option for additional ports. This configures TShark's Modbus TCP dissector and request direction; it is an operator-supplied decoding assumption, not independent protocol confirmation. Port 502 remains enabled. A port number alone never creates a write finding: decoded Modbus function fields and MBAP protocol identifier zero must also be present. Some TShark versions expose function fields for nonzero identifiers; these frames are explicitly left unassessed. Existing flow service labels remain port-based indicators.

## Authorization rules

The JSON object must contain exactly `modbus_write_allowlist`, a list of rules. Each rule requires `source`, an exact literal IP address, and optionally `destinations`, a nonempty list of exact literal IP addresses. Hostnames, CIDRs, wildcards, unknown keys and non-string IP addresses are rejected. Rules are additive: any matching rule permits the request.

- With `destinations`, the source is allowed only for those destinations.
- Omitting `destinations` explicitly permits that source to write to any destination. Prefer destination-scoped rules where possible.
- An empty allowlist flags every detected write request. Missing or invalid policy causes an error, never implicit authorization.

This policy is an offline classification input. It is separate from signed active-check approvals and does not authorize connections. IP addresses identify observed endpoints, not authenticated users or machines; spoofing, NAT, shared hosts and capture placement affect interpretation.

## Supported operations and evidence

| Modbus function | Operation |
| --- | --- |
| 5 | Write Single Coil |
| 6 | Write Single Register |
| 15 | Write Multiple Coils |
| 16 | Write Multiple Registers |
| 21 | Write File Record |
| 22 | Mask Write Register |
| 23 | Read/Write Multiple Registers |

Each decoded request is recorded in `write_operations` in report.json, the HTML write-request table and `write_operations.csv`, including frame number, PDU index within that frame, endpoints, function and authorization outcome. Unexpected writes add Review findings to the existing reports. Multiple PDUs per frame are kept distinct. Retransmitted requests can appear more than once; counts represent observed decoded requests, not unique transactions.

TShark determines protocol/function fields. Request direction requires the destination to use a configured server port and the source to use a different, non-server port. Replies (including orphan replies), exceptions and ambiguous directions are excluded. Wireshark itself uses configured server ports to distinguish Modbus TCP request/reply direction. A captured request is evidence of an attempted operation; it does not prove the destination accepted or performed it.

`write_analysis` records evaluated rules, decoded Modbus PDU and write counts, ambiguous directions, malformed frames, unassessed protocol identifiers, unassessed encapsulation contexts, other/unassessed requests, packet cap, explicit decode ports and dissector diagnostics. These fields also appear in HTML. Malformed frame counting covers packets returned by the Modbus display filter, not the entire capture. Other/unassessed requests are not classified as safe or authorized.

## Coverage limits

Only the seven functions above are assessed. Other Modbus functions, diagnostics and vendor-specific commands can also change device state. Other industrial protocols are not assessed. Encrypted traffic, missing packets, malformed messages, unrecognized protocols and ambiguous direction can hide writes. Frames with multiple IP/TCP layers are left unassessed to avoid attributing a command to an outer tunnel endpoint. Dissection and TCP reassembly depend on TShark and capture completeness. No findings must never be interpreted as proof that no writes occurred.

The input is capped at 256 MiB, processing at `--max-packets` (default 500,000; maximum 1,000,000), TShark execution at 120 seconds, and returned JSON at 256 MiB before loading. TShark temporarily writes dissection data to local temporary files; the output-size check occurs after execution and is not a live disk quota. Limits or errors can prevent a complete assessment. Use bounded captures and protect local temporary storage and reports as sensitive evidence. No report is emitted for a failed TShark run. Existing reports in an output directory are not deleted on failure; use a fresh directory to distinguish runs.

## Validation

`python -m pytest -q tests/test_industrial.py` exercises actual TShark dissection of synthetic offline PCAPs: every supported function, request/reply separation, orphan replies, read requests, exception replies, nonstandard ports, multiple PDUs, and source/destination policy matching. TShark-dependent tests skip when the executable is absent; CI installs it explicitly. This is software regression coverage, not device-vendor or production OT certification.
