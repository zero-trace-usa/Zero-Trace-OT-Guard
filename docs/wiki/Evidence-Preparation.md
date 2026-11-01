# Evidence preparation

Analyze an existing export or capture obtained through your site's approved process. OT Guard's offline command does not discover devices, create a capture or contact the captured network. Keep an original copy, record provenance, and work with a protected evidence directory.

## Input directory

```text
evidence/
  flows.csv        OR capture.pcap
  assets.csv       optional
  advisories.csv   optional
  rules.csv        optional
```

Filenames are exact. Ordinary analysis gives CSV precedence when both primary inputs exist. `--write-policy` refuses that ambiguous directory; provide a separate PCAP-only input directory.

## Flow CSV

Use this header:

```csv
src_ip,dst_ip,protocol,src_port,dst_port,packets,bytes
192.0.2.10,192.0.2.20,TCP,51515,502,20,1200
```

| Field | Accepted content |
| --- | --- |
| `src_ip`, `dst_ip` | Literal IPv4 or IPv6 addresses; no hostnames |
| `protocol` | TCP or UDP; normalized to uppercase |
| `src_port`, `dst_port` | Integer 0–65535 |
| `packets`, `bytes` | Nonnegative integers; empty metrics normalize to zero |

A flow row is metadata, not a decoded command. A destination port of 502 can produce an indicative service label but cannot establish a Modbus write.

## Optional inventory

```csv
ip,vendor,product,version,zone
192.0.2.10,ExampleCo,Engineering Workstation,1.0,Engineering
192.0.2.20,ExampleCo,PLC,1.0,Control
```

The `ip` field associates inventory with observed addresses. Provide consistent, canonical address spelling. Uninventoried observed addresses receive an Unknown zone. Supplied inventory entries also appear in the asset list, even if the evidence does not show traffic for them. These are operator-supplied attributes, not authenticated device discoveries.

## Optional zone rules

```csv
src_zone,dst_zone,dst_port,action
Engineering,Control,502,deny
```

A matching observed source/destination zone pair and destination port with action `deny` creates a policy-conflict finding. `*` matches any destination port. Zone names must match inventory values. Rules describe review policy; they do not configure a firewall or block packets. This schema does not express write-command authorization; use the separate JSON write policy for that.

## Optional advisory data

```csv
advisory_id,vendor,product,version
EXAMPLE-REVIEW-ONLY,ExampleCo,PLC,1.0
```

Vendor and product matches are case-insensitive. A supplied advisory version matches the inventory version exactly; a blank advisory version does not restrict the match. There is no live advisory download, affected-version range engine or vulnerability confirmation. The example above is illustrative, not a real vulnerability advisory.

## Supported PCAP

Use **classic PCAP, Ethernet link type and IPv4 TCP/UDP traffic**, named `capture.pcap`. The flow ingestion path does not support PCAPNG or IPv6 decoding. Fragmented IPv4 traffic is skipped by the metadata reader. VLAN tags can be traversed to find IPv4, but VLAN identity is not retained for policy decisions. PCAP byte totals are zero because the metadata reader does not aggregate bytes.

The optional TShark path decodes Modbus commands, but the CLI still runs this flow reader first. Installing TShark therefore does not make PCAPNG or IPv6 captures supported by this CLI. Converting a capture's container does not convert its link type, IP version, encryption or missing packets.

## Limits and incomplete evidence

| Input or operation | Limit |
| --- | --- |
| Each CSV | 20 MiB and 100,000 rows |
| PCAP | 256 MiB |
| Packet count | Default 500,000; selectable 1–1,000,000 |
| Write-policy JSON | 20 MiB |
| TShark execution | 120 seconds |
| Returned TShark JSON | 256 MiB before loading; checked after process completion |

For a justified larger packet budget within the supported range:

```sh
python -m otguard analyze --input evidence --output reports/larger-review --max-packets 1000000
```

Inspect JSON `evidence_metadata` warnings and, when enabled, `write_analysis`. The cap is a processing limit, not a statement that the entire capture was assessed. TShark temporarily writes dissection data to local storage; the returned-output check is not a live disk quota.

Next: [write detection](Write-Detection.md) or [report interpretation](Reports-and-Triage.md).
