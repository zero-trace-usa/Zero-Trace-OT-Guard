# Security and evidence handling

## Processing boundaries

`analyze` reads supplied files and writes local reports. Optional TShark uses file-read mode with name resolution disabled. Offline analysis does not contact the captured devices or send industrial commands. Installation/build tooling may need network access before offline use. Explicit active-check execution is a separate traffic-generating workflow.

Use a suitable analysis workstation with an updated TShark installation. Captures are untrusted input; the tool's resource limits do not constitute a sandbox or a production safety guarantee.

## Protect inputs, temporary files and outputs

Captures may contain payloads and sensitive topology. Reports expose addresses, zones, products and write-authorization rules. TShark temporarily writes dissection JSON to local temporary storage even though final write records contain selected metadata. Protect the analysis host, temporary storage, backups and exports accordingly.

On a suitable Unix analysis workstation, a restrictive umask before running commands helps limit newly created file access:

```sh
umask 077
```

Use approved OS access controls on other systems. Preserve the original evidence and record its source, collection window, capture location, software version, run command and policy version. Hash evidence using your supported tools, such as `sha256sum` or PowerShell `Get-FileHash`. The application does not create a signed chain-of-custody manifest or tamper-evident report.

Use unique output directories and an approved retention process. Do not upload unredacted captures, reports or inventories to public issues or documentation. CSV exports neutralize common formula prefixes, but spreadsheets and imported evidence should still be treated as untrusted.

## Keep authorization separate

The Modbus source/destination allowlist classifies observed requests. It does not authorize network contact. Active approvals are separately signed using a shared key; avoid committing keys, live approvals and audit files. A verifier holding the HMAC key can also sign, so that key is not independent approver identity verification.

## Interpretation limits

- An observed request is not proof of a completed write or physical process change.
- An IP allowlist is not machine/user authentication.
- Missing or undecoded evidence is not evidence of safe operation.
- Advisory correlation does not verify vulnerability or exploitability.
- Per-invocation TCP budgets do not enforce aggregate packet rates.
- Reports and active audit logs are not tamper-evident.

These limits guide interpretation of the actual tool, rather than granting permission for production deployment. See the [safety runbook](https://github.com/zero-trace-usa/Zero-Trace-OT-Guard/blob/main/docs/SAFETY_ENGINE.md) and [validation status](https://github.com/zero-trace-usa/Zero-Trace-OT-Guard/blob/main/docs/VALIDATION.md) for supporting evidence.

Contributors must follow the repository's [Git privacy identity policy](https://github.com/zero-trace-usa/Zero-Trace-OT-Guard/blob/main/docs/PRIVACY.md).
