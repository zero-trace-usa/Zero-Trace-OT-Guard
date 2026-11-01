# Installation

## Requirements

| Component | When it is needed |
| --- | --- |
| Python 3.10 or newer | Every workflow; Linux CI covers 3.10–3.13 |
| Git | Cloning source and updating a checkout; a source archive is an alternative |
| Python virtual environment support | Recommended to isolate installation |
| TShark on PATH | Optional Modbus write detection only |
| Build-tool downloads | Installation/build time; analysis can then run offline |
| Signing/verification key and signed approval | Separate active-check workflow only |

There are no Python runtime dependencies for basic offline analysis. Development dependencies are optional. Windows and macOS commands are documented, but those operating systems are not covered by CI. TShark write regressions were checked locally with versions 4.0.17 and 4.4.18 on Linux.

## Linux and macOS

Run these commands in a directory where you want the checkout:

```sh
git clone --branch v1.0.0-rc.6 --depth 1 https://github.com/zero-trace-usa/Zero-Trace-OT-Guard.git
cd Zero-Trace-OT-Guard
python3 -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/python -m otguard --version
```

Expected version: `Zero-Trace OT Guard 1.0.0rc6`.

Activate for the shorter commands used throughout this guide:

```sh
source .venv/bin/activate
```

On Debian/Ubuntu, missing venv support is normally resolved with the OS `python3-venv` package. Use your organization's supported package installation process.

## Windows PowerShell

```powershell
git clone --branch v1.0.0-rc.6 --depth 1 https://github.com/zero-trace-usa/Zero-Trace-OT-Guard.git
cd Zero-Trace-OT-Guard
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install .
.\.venv\Scripts\python.exe -m otguard --version
```

Activation is optional. If PowerShell allows it, run `.\.venv\Scripts\Activate.ps1`. Otherwise use `.\.venv\Scripts\python.exe` wherever the guide says `python`; no execution-policy change is necessary.

## Install optional TShark

For Debian/Ubuntu:

```sh
sudo apt-get update
sudo apt-get install tshark
tshark --version
```

Live-capture privileges are unnecessary for reading a file. If package configuration asks whether non-administrators should capture live packets, offline analysis does not require enabling that feature. On other systems, use the supported Wireshark/TShark installer or package manager and add the TShark executable directory to PATH. A GUI Wireshark installation alone does not guarantee `tshark` is available in your terminal.

## Source archives and wheels

Download from the project's GitHub release, and verify selected assets against the attached `SHA256SUMS`. On Linux, `sha256sum FILENAME` prints a digest to compare with the matching manifest entry. On PowerShell, use `Get-FileHash FILENAME -Algorithm SHA256`. A matching manifest digest checks download integrity; it is not independent publisher authentication.

A source ZIP or source distribution includes examples and documentation. Open a terminal in its extracted root and follow the commands starting with virtual-environment creation. A wheel installs the CLI and packaged branding but does not install the example evidence directory. Obtain the examples from matching source separately.

Do not use `pip install zero-trace-ot-guard` as the source installation method: this distribution is not currently published to PyPI. Do not disable TLS or package verification to work around installation failures.

Next: [run the sample](Quick-Start.md).
