# Modbus write detection and authorization

Use this mode to review whether captured Modbus/TCP write requests originated from approved sources and, optionally, targeted approved destinations. It operates on existing evidence and sends no traffic to the captured network.

## Requirements

- A working installation and `tshark --version` in the same terminal.
- A supported `capture.pcap` in the input directory, without `flows.csv`.
- An explicitly reviewed JSON policy. The policy file may live outside the evidence directory.

## Define the policy

Copy `examples/write-policy.example.json` to a local `write-policy.json`, then replace the documentation addresses with the actual approved endpoints:

```json
{
  "modbus_write_allowlist": [
    {
      "source": "192.0.2.10",
      "destinations": ["192.0.2.20"]
    }
  ]
}
```

This illustrative rule allows the listed source to issue the seven supported write functions to the listed destination. It does not permit that source to write elsewhere. A different source remains unexpected even when it targets that approved destination.

| Policy choice | Meaning |
| --- | --- |
| Exact source plus destination list | Restrict that source to those destinations |
| Exact source without `destinations` | Explicitly permit that source to any destination |
| Multiple rules | Any matching rule permits the request |
| Empty allowlist | Every detected write request is unexpected |
| Invalid/missing policy | Analysis fails; it does not silently authorize traffic |

Only `modbus_write_allowlist` is accepted at the top level. Each rule accepts `source` and optional `destinations`. Addresses must be strings containing exact IPs; no hostnames, CIDRs or wildcards. A present destination list must be nonempty. Additional keys, including function-specific permissions, are not supported. The current CLI capture path is IPv4-only even though the policy validator accepts literal IP address syntax.

An IP address identifies an observed endpoint, not an authenticated machine or operator. NAT, shared workstations, spoofing and capture placement affect attribution. This offline allowlist does not grant permission to run active network checks.

## Analyze

```sh
python -m otguard analyze --input evidence --output reports/write-review-001 --write-policy write-policy.json
```

For a known nonstandard Modbus server port:

```sh
python -m otguard analyze --input evidence --output reports/write-review-1502 --write-policy write-policy.json --modbus-tcp-port 1502
```

Repeat `--modbus-tcp-port` for additional ports. Port 502 remains enabled. These options configure TShark dissection and server direction; they are operator-supplied decoding assumptions, not independent proof of protocol identity.

## Supported commands

| Function code | Operation |
| --- | --- |
| 5 | Write Single Coil |
| 6 | Write Single Register |
| 15 | Write Multiple Coils |
| 16 | Write Multiple Registers |
| 21 | Write File Record |
| 22 | Mask Write Register |
| 23 | Read/Write Multiple Registers |

A finding requires decoded Modbus function fields **and MBAP protocol identifier zero**. Some TShark versions expose function fields for other identifiers; those frames are deliberately unassessed. The destination must use a configured server port and the source must use a different, non-server port. Ambiguous direction is excluded. Replies, including orphan replies and exception responses, are excluded.

## Review the evidence

Each write record includes `frame`, `pdu`, `source`, `destination`, `protocol`, `function_code`, `operation` and `authorized`. `pdu` distinguishes decoded messages within the same frame. Use the frame reference in the original capture to investigate. Multiple PDUs remain separate; retransmissions can produce multiple observations. Counts are not deduplicated successful transactions.

Unexpected requests create Review findings. Authorized requests remain visible in `write_operations` and `write_operations.csv`; they are not automatically harmless. The captured request does not prove device acceptance or a physical process change. The reports do not currently include register-level authorization, authenticated user identity, transaction-level success or process safety validation.

Other Modbus functions and diagnostics can also change state. Other industrial protocols, encrypted/undecoded traffic, incomplete captures and multiply encapsulated contexts are outside this detection coverage. No detected writes is not proof that the capture contains none.

Next: [reports and triage](Reports-and-Triage.md).
