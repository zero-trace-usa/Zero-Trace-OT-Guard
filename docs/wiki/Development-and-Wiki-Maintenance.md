# Development and Wiki maintenance

## Development setup

Use the existing checkout in an isolated cloud task; a Git worktree is unnecessary unless explicitly requested. From the checkout root, activate your virtual environment and install development dependencies:

```sh
python -m pip install -e '.[dev]'
python -m pytest -q
python -m compileall -q src
python -m bandit -q -r src -s B101
python -m pip check
python -m build
```

TShark must be on PATH for actual-dissector integration tests. Those tests skip when it is absent; a passing run with skips is not full write-detection validation. The published supported-version gate covers Linux Python 3.10–3.13. Existing loopback tests need local socket support and do not contact OT devices.

For clean installed-wheel verification, install the intended wheel into a fresh virtual environment and run that Python on `tests/wheel_smoke.py` from the checkout. Source archives include this helper and its synthetic capture fixture.

## Canonical documentation

Use a current main-branch checkout for documentation maintenance; a release-tag checkout may not contain documentation added after publication. The reviewable Wiki source lives in `docs/wiki` in the main repository. Application behavior is defined by the code and release-specific documentation; update this guide whenever supported commands, policies, outputs or limits change. Keep Home's version scope and examples aligned with the intended release. Do not advertise future roadmap features as implemented.

The repository copy uses `.md` links so it works before GitHub Wiki is enabled. `scripts/prepare_wiki.py` prepares copies with GitHub Wiki page links, preserving the repository source. `_Sidebar.md` supplies Wiki navigation.

## Enable and initialize GitHub Wiki

A repository owner or administrator must enable **Wikis** in the repository's Settings → General → Features. If no Wiki repository exists yet, open the Wiki tab and save an initial Home page. GitHub Wiki uses a separate Git repository; application-repository access alone does not establish that its Wiki endpoint exists or is authorized.

Once the Wiki is enabled and initialized, publish the prepared pages from the application checkout:

```sh
git clone https://github.com/zero-trace-usa/Zero-Trace-OT-Guard.wiki.git ../otguard-wiki
python scripts/prepare_wiki.py --output ../otguard-wiki
git -C ../otguard-wiki config --local user.name Zero-Trace
git -C ../otguard-wiki config --local user.email 78784941+zero-trace-usa@users.noreply.github.com
git -C ../otguard-wiki var GIT_AUTHOR_IDENT
git -C ../otguard-wiki var GIT_COMMITTER_IDENT
git -C ../otguard-wiki add -- '*.md'
git -C ../otguard-wiki diff --cached --stat
git -C ../otguard-wiki commit -m "Publish Zero-Trace OT Guard user guide"
git -C ../otguard-wiki push origin HEAD
```

Inspect the staged diff before committing. The helper overwrites its managed page filenames in the selected directory; preserve any independently maintained pages or edits first. If there are no changes, skip commit/push. For later updates, pull the Wiki checkout before preparing pages and resolve concurrent edits normally. Never force-push an independently edited Wiki merely to make publication succeed.

## Documentation verification

Run the bundled sample and compare its expected 3 assets, 2 flows and 2 findings. Review CLI options against `--help`, validate policy JSON through the installed validator, check local page links and test `prepare_wiki.py` in a disposable output directory. Verify source-archive inclusion when adding new documentation or helpers.

Use the project's established privacy author/committer identity and follow AGENTS.md. Do not reintroduce personal identity aliases, credentials or real-site evidence in documentation.
