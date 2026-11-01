# Command reference

Run from the source checkout with its virtual environment activated. Paths are relative to your current directory; quote paths containing spaces. `python -m otguard` and the installed `otguard` command use the same CLI.

```sh
python -m otguard --version
python -m otguard --help
python -m otguard analyze --help
python -m otguard active-check --help
python -m otguard sign-approval --help
```

## Analyze

```sh
python -m otguard analyze --input DIRECTORY --output DIRECTORY
```

| Option | Default/requirement | Meaning |
| --- | --- | --- |
| `--input DIRECTORY` | Required | Directory containing flows.csv or capture.pcap |
| `--output DIRECTORY` | `reports` | Create output directory; report files are overwritten |
| `--max-packets INTEGER` | `500000`; 1–1000000 | PCAP processing cap; unused for CSV |
| `--write-policy FILE` | Optional | Enable TShark Modbus write review using the explicit JSON allowlist |
| `--modbus-tcp-port INTEGER` | Optional, repeatable; 1–65535 | Additional Modbus server/decode port; requires --write-policy |

CSV wins when both primary inputs exist, except write analysis explicitly rejects directories containing flows.csv. Optional input CSVs are assets.csv, advisories.csv and rules.csv. See [evidence preparation](Evidence-Preparation.md) and [write detection](Write-Detection.md).

## Sign approval

```sh
python -m otguard sign-approval --approval FILE
```

Signs the JSON file **in place** using securely provisioned `OTGUARD_APPROVAL_KEY`. This does not grant operational authorization. The offline analysis command does not read or require that key.

## Active check

| Option | Default/requirement | Meaning |
| --- | --- | --- |
| `--approval FILE` | Required | Signed approval JSON |
| `--target IP` | Required, repeatable | Exact approved IP; all selected target/port combinations are planned |
| `--port INTEGER` | Required, repeatable | Exact approved port, subject to the industrial denylist |
| `--ack-authorized` | Required acknowledgement | Does not grant authorization |
| `--execute` | Off | Explicitly execute; omission produces an offline plan |
| `--plan-id IDENTIFIER` | Required with --execute | Exact identifier of the reviewed plan |
| `--output FILE` | `active-results.json` | Plan or execution JSON output |
| `--stop-file FILE` | None | Existing file requests cooperative stop |
| `--audit-file FILE` | `active-audit.jsonl` | Append execution audit records |

Parent directories for active output/audit files must exist. The active command is separate from evidence analysis and requires the [active-check prerequisites](Active-Checks.md).

## Exit status

| Status | Meaning |
| --- | --- |
| `0` | Command completed; findings or unsuccessful connection outcomes may still exist |
| `2` | Argument, input, policy, signature, filesystem or handled analysis error |
| `3` | Active execution interrupted by stop, expiry or consecutive-failure cutoff |

Do not infer absence of findings from exit zero. Inspect JSON results and metadata. Do not infer absence of transmitted traffic from an active-command error.
