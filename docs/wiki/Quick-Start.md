# Quick start: offline analysis

These commands assume you are in the source checkout's root with its virtual environment activated. Use the explicit virtual-environment Python from [installation](Installation.md) if activation is unavailable.

## Verify the installed command

```sh
python -m otguard --version
python -m otguard analyze --help
```

## Analyze the bundled CSV sample

```sh
python -m otguard analyze --input examples/sample --output reports/sample-first-run
```

Expected summary:

```json
{
  "observed_assets": 3,
  "flows": 2,
  "findings": 2
}
```

The output directory contains `report.html`, `report.json`, `assets.csv`, `flows.csv` and `findings.csv`. Open `report.html` from your filesystem. For example, Windows users can run:

```powershell
Start-Process .\reports\sample-first-run\report.html
```

The two findings are a sample zone-policy conflict and an illustrative inventory advisory match. They are not confirmed vulnerabilities. The sample advisory is demonstration data, not a bundled live threat feed. The sample CSV does not contain industrial commands and cannot demonstrate write-command detection.

## Analyze your own evidence

Choose an input folder containing either `flows.csv` or the supported `capture.pcap`:

```sh
python -m otguard analyze --input evidence --output reports/site-review-001
```

Replace `evidence` with your directory, quoting paths that contain spaces. If both files exist, ordinary analysis chooses CSV. Write analysis instead requires a PCAP directory without `flows.csv`.

Use a new output directory for each review. Reusing a directory overwrites report files; files left from an earlier mode or failed run can be misleading. An exit status of zero means the command completed, even when findings exist.

## Add write analysis when appropriate

Install TShark, prepare a reviewed policy from `examples/write-policy.example.json`, and use a directory containing `capture.pcap` without `flows.csv`:

```sh
python -m otguard analyze --input evidence --output reports/write-review-001 --write-policy write-policy.json
```

Do not treat the example's documentation addresses as your actual authorization policy. Follow [write detection](Write-Detection.md) before interpreting its findings.

Next: [prepare evidence](Evidence-Preparation.md) and [review reports](Reports-and-Triage.md).
