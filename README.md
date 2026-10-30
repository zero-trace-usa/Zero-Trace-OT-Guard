# Zero-Trace OT Guard

Passive-first OT network evidence analysis with separately authorized TCP connectivity checks.

**Current release: [v1.0.0-rc.4](https://github.com/zero-trace-usa/Zero-Trace-OT-Guard/releases/tag/v1.0.0-rc.4), an engineering prerelease.** Suitable for offline analysis and controlled lab evaluation. Production OT safety certification and vendor compatibility validation have not been completed.

## Install and run

Requires Git and Python 3.10 or newer. CI covers Python 3.10–3.13 on Linux. Windows and macOS commands are provided, but those operating systems have not been validated in CI. No runtime dependencies, API keys, background services or device access are required for offline analysis. Internet access is needed to clone and fetch Python build tools during installation.

### Linux and macOS

```sh
git clone --branch v1.0.0-rc.4 --depth 1 https://github.com/zero-trace-usa/Zero-Trace-OT-Guard.git
cd Zero-Trace-OT-Guard
python3 -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/python -m otguard --version
.venv/bin/python -m otguard analyze --input examples/sample --output reports
```

### Windows PowerShell

```powershell
git clone --branch v1.0.0-rc.4 --depth 1 https://github.com/zero-trace-usa/Zero-Trace-OT-Guard.git
cd Zero-Trace-OT-Guard
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install .
.\.venv\Scripts\python.exe -m otguard --version
.\.venv\Scripts\python.exe -m otguard analyze --input examples/sample --output reports
Start-Process .\reports\report.html
```

Expected version: `Zero-Trace OT Guard 1.0.0rc4`. Expected sample summary: **3 observed assets, 2 flows, 2 findings**. Open `reports/report.html` locally. JSON and three CSV reports are saved alongside it. Findings are review indicators, not confirmed vulnerabilities.

If Git is unavailable, download and extract the release's GitHub source ZIP, open a terminal in its extracted root, then follow the commands starting with virtual-environment creation. The source distribution also includes documentation and examples. A wheel-only install provides the CLI; sample data must be obtained from a source archive separately. Release assets include SHA256SUMS for download integrity checks.

### Command names

| Name | Purpose |
| --- | --- |
| Zero-Trace OT Guard | Product name |
| `zero-trace-ot-guard` | Python distribution name; not currently published to PyPI |
| `otguard` | Installed command and Python module |
| `v1.0.0-rc.4` / `1.0.0rc4` | GitHub tag / equivalent Python package version |

Do not use `pip install zero-trace-ot-guard` as the installation method: this project is distributed through its GitHub release assets and source repository.

For shorter commands, activate the environment with `source .venv/bin/activate` on Linux/macOS or `.\.venv\Scripts\Activate.ps1` in PowerShell. If PowerShell policy blocks activation, continue using the explicit Python path above; no policy change is needed. After activation, `otguard` and `python -m otguard` are equivalent.

## Analyze your evidence

With the environment activated:
```sh
python -m otguard analyze --input examples/sample --output reports
python -m otguard analyze --help
```

Replace `examples/sample` with your evidence directory, quoting paths containing spaces. Supply `flows.csv` or a classic Ethernet/IPv4 `capture.pcap`. CSV takes precedence if both exist. Optional files are `assets.csv`, `advisories.csv` and `rules.csv`; use the sample headers as templates. Reports in the output directory are overwritten on rerun, so choose a new directory when preserving evidence.

PCAP ingestion retains TCP/UDP metadata, not protocol payloads. PCAPNG, IPv6 packet decoding and fragmented IPv4 packets are unsupported. VLAN tags are traversed to locate IPv4; VLAN identities are not retained or used for policy assessment. PCAP byte totals are zero because byte accounting is not implemented. The default processing cap is 500,000 packets; maximum 1,000,000. Inspect JSON evidence warnings for incomplete captures. See [architecture](docs/ARCHITECTURE.md) and [settings](docs/CONFIGURATION.md).

## Optional authorized connectivity checks

Offline analysis does not need this workflow. TCP handshakes can affect fragile equipment. Active execution requires written asset-owner authorization, site-specific hazard assessment, a signed approval, an acknowledgement and a reviewed plan identifier. The built-in industrial-port denylist is not comprehensive.

1. Read the [safety policy and operator runbook](docs/SAFETY_ENGINE.md).
2. Have the authorized approver copy `examples/approval.example.json`, replace every placeholder including expiry, review scope and budgets, and follow the [signing instructions](docs/SECURITY_HARDENING.md).
3. With the environment activated, review the offline plan:
   ```sh
   python -m otguard active-check --approval approval.json --target 192.0.2.10 --port 443 --ack-authorized
   ```
4. Only in the separately approved environment, follow the runbook's execution instructions using the returned `plan_id`.

Execution is serial and enforces per-invocation connection budgets, global spacing, per-host cooldown, expiry and a failure cutoff. Connection budgets do **not** enforce packet rates or coordinate multiple processes. Audit logs are not tamper-evident. No protocol commands, credential tests, exploitation or vulnerability confirmation are performed.

## Help and troubleshooting

- Run `python -m otguard --help`, `analyze --help`, `active-check --help` or `sign-approval --help` within the virtual environment.
- `No module named otguard`: use the same virtual-environment Python for installation and execution.
- Missing `venv` on Debian/Ubuntu: install the OS's Python venv package before creating the environment.
- `Expected flows.csv or capture.pcap`: check `--input` and the filenames; source examples are not included inside a wheel.
- Approval, signature or plan mismatch errors: review the [settings reference](docs/CONFIGURATION.md); never bypass signature validation.

See [validation evidence](docs/VALIDATION.md), [security policy](SECURITY.md), [changelog](CHANGELOG.md) and [roadmap](ROADMAP.md).

## Development

Use the existing checkout; create and activate a virtual environment, then:
```sh
python -m pip install -e '.[dev]'
python -m pytest -q
python -m compileall -q src
python -m bandit -q -r src -s B101
python -m build
```

Release publication is gated on the multi-version CI test matrix and installed-wheel smoke checks. See [contributing](CONTRIBUTING.md) and the [release checklist](docs/SAFETY_ENGINE.md).
