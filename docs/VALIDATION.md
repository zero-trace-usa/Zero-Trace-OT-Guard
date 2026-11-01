# Validation status — v1.0.0-rc.6

## Release verification

The local release validation covers Linux Python 3.10, 3.11, 3.12 and 3.13 with TShark 4.4.18 (write-analysis regressions also checked with 4.0.17):

- 76 unit, regression and loopback integration tests, including 37 write-analysis tests. Actual TShark captures exercise all seven supported write functions, source/destination authorization, read and reply exclusions, exception replies, nonstandard ports, multiple PDUs, real packet caps, invalid captures and non-Modbus protocol identifiers. Additional checks cover invalid policies, missing TShark, subprocess errors/timeouts, ambiguous direction and unassessed encapsulation contexts.
- Source compilation and Bandit (B101 excluded, matching CI).
- Source distribution and wheel builds; source archive examples and documentation.
- Clean installed-wheel CLI version and offline sample: 3 assets, 2 flows and 2 findings, with standalone embedded branding.
- Clean installed-wheel Modbus smoke check: an unexpected register-write request and its reply produce one write record and one Review finding.

The tag-triggered GitHub Actions workflow repeats the supported Python 3.10–3.13 matrix, installs TShark, checks source resources and both installed-wheel workflows, and publishes the Python 3.12 distributions with SHA256SUMS only after all test jobs succeed. Public run status is recorded by GitHub Actions; preparing this document does not establish that the tagged run has passed. Windows and macOS have not been validated in CI. TShark versions outside those exercised locally or in CI have not been independently certified.

## Published rc.6 verification

The [tagged release workflow](https://github.com/zero-trace-usa/Zero-Trace-OT-Guard/actions/runs/41291483194) passed for release commit `8ffdf58` and published [v1.0.0-rc.6](https://github.com/zero-trace-usa/Zero-Trace-OT-Guard/releases/tag/v1.0.0-rc.6) as an engineering prerelease. The Python 3.10–3.13 test/build matrix and release job completed successfully. Main-branch CodeQL also passed for the release code.

After publication, all five downloadable package/image assets were downloaded and verified against the published SHA256SUMS. Fresh environments installed both the public wheel and public source distribution. Each passed CLI version, offline sample (3 assets, 2 flows, 2 findings) and Modbus write smoke checks (one unexpected write record and finding, excluding its reply). The public wheel also rendered embedded branding successfully.

Public CI identified a dissector-version difference: a TShark version can expose Modbus function fields for a nonzero MBAP protocol identifier. The released code explicitly requires identifier zero, and the regression test remains enabled. Frames with missing, nonzero or mixed identifiers are unassessed rather than treated as Modbus writes.

## Interpretation and remaining limits

No hardware-in-the-loop validation, device-vendor compatibility certification, parser fuzz campaign or independent security assessment has been performed. Captured Modbus write requests indicate attempted operations, not successful execution. Only documented functions are assessed. Configured server ports determine request/reply direction; unknown or ambiguous contexts are unassessed. An allowlisted IP is not an authenticated host identity. See [write detection](WRITE_DETECTION.md) for policy semantics, limits and all exclusions.

The flow parser retains supported metadata only. PCAPNG and IPv6 capture decoding remain unsupported by the CLI flow ingestion path. Advisory correlation is inventory-based and does not verify exploitability. Absence of findings does not establish absence of unsafe operations or vulnerabilities.

Active connection limits are per invocation, not aggregate across operators or processes. Audit logging is not tamper-evident. Shared-key approval signing relies on key custody; the stop file is cooperative, not a safety-rated emergency-stop system. A matching plan identifier is not evidence of independent human review. See SAFETY_ENGINE.md and SECURITY_HARDENING.md for operating constraints and production gates.

Brand assets remain embedded in standalone HTML reports and packaged distributions. Account-avatar and repository social-preview uploads are manual GitHub settings operations; no account image change is claimed.
