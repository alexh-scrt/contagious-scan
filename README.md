# contagious_scan

> Audit Git repositories for DPRK-style "Contagious Interview" supply chain attacks — before they ship.

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## What It Does

`contagious_scan` is a security CLI tool that detects indicators of the *Contagious Interview* campaign — a DPRK-attributed supply chain attack that targets software developers through trojanised npm packages and Python libraries. It scans package manifests, post-install scripts, CI/CD configs, and source files for known malicious patterns including **BeaverTail** infostealer payloads and **InvisibleFerret** backdoor stagers. Run it as a one-off audit on any local or remote Git repository, or wire it into a pre-push hook to block compromised code before it ever reaches a remote.

---

## Quick Start

```bash
# Install
pip install contagious_scan

# Scan the current repository
contagious-scan scan .

# Scan a remote repository
contagious-scan scan https://github.com/org/suspicious-repo --remote

# Install as a Git pre-push hook (blocks pushes on critical findings)
contagious-scan install-hook .
```

That's it. Any critical or high-severity findings are printed to the terminal and the command exits with a non-zero code — making it CI-friendly out of the box.

---

## Features

- **RAT payload detection** — Regex and hash-based signatures for BeaverTail JS loaders and InvisibleFerret Python stagers, plus obfuscated base64/hex `eval`/`exec` chains across JS, Python, and shell files.
- **Package manifest auditing** — Flags malicious `postinstall`, `prepare`, and `preinstall` lifecycle hooks in `package.json`, `setup.py`, `setup.cfg`, and `pyproject.toml`.
- **Git-aware scanning** — Inspects only staged files in hook mode, the full working tree in audit mode, or clones a remote URL on demand.
- **Pre-push hook installation** — One command blocks pushes when critical-severity findings are detected, with a `--ci-override` flag for automated pipelines.
- **Structured reporting** — Rich color-coded terminal tables, machine-readable JSON, and plain-text output with severity levels (`critical` / `high` / `medium` / `info`), file locations, matched pattern descriptions, and remediation guidance.

---

## Usage Examples

### Audit a local repository

```bash
# Default rich terminal output
contagious-scan scan /path/to/repo

# Output as JSON (useful for piping into other tools)
contagious-scan scan /path/to/repo --format json

# Only surface high and critical findings
contagious-scan scan /path/to/repo --min-severity high
```

### Audit a remote repository

```bash
contagious-scan scan https://github.com/org/repo --remote
```

### Scan only staged files (manual hook simulation)

```bash
contagious-scan scan . --staged-only
```

### Install the pre-push hook

```bash
# Standard installation — blocks pushes on critical findings
contagious-scan install-hook /path/to/repo

# CI-friendly: hook runs but never blocks the push
contagious-scan install-hook . --ci-override

# Check whether the hook is already installed
contagious-scan install-hook . --status

# Remove the hook
contagious-scan install-hook . --uninstall
```

### Re-render a saved JSON report

```bash
# Save findings to disk
contagious-scan scan . --format json > findings.json

# Re-render later as a rich table
contagious-scan report findings.json --format rich
```

### Example terminal output

```
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ File                            ┃ Severity  ┃ Description                         ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ packages/utils/package.json     │ CRITICAL  │ Malicious postinstall lifecycle hook │
│ src/loader.js                   │ HIGH      │ BeaverTail base64 eval chain         │
│ scripts/setup.py                │ HIGH      │ InvisibleFerret stager pattern       │
│ .github/workflows/ci.yml        │ MEDIUM    │ Suspicious outbound curl in CI step  │
└─────────────────────────────────┴───────────┴─────────────────────────────────────┘
4 findings (1 critical, 2 high, 1 medium)
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0`  | No findings at or above the minimum severity threshold |
| `1`  | One or more findings detected |
| `2`  | Scan error (invalid path, git error, etc.) |

---

## Project Structure

```
contagious_scan/
├── __init__.py          # Package init — version and top-level API
├── cli.py               # Click CLI entry point (scan, install-hook, report)
├── scanner.py           # Scan pipeline orchestration and file discovery
├── detectors.py         # Detector functions: RAT patterns, loaders, hooks, CIDDs
├── signatures.py        # Static IOC database: regexes, hashes, package names
├── git_utils.py         # Staged file enumeration, repo walk, remote cloning
├── reporter.py          # Rich/JSON/plain output rendering and exit codes
└── hook_installer.py    # Git pre-push hook writer and manager

tests/
├── fixtures/
│   ├── malicious_package.json   # npm package.json with injected postinstall payload
│   └── malicious_setup.py       # setup.py with obfuscated InvisibleFerret loader
├── test_detectors.py    # Unit tests for each detector function
├── test_scanner.py      # Integration tests against temporary git repo fixtures
├── test_reporter.py     # Reporter formatting and exit code tests
├── test_cli.py          # CLI command and flag tests
├── test_git_utils.py    # Git utility function tests
├── test_hook_installer.py
├── test_signatures.py
└── test_init.py

pyproject.toml
README.md
```

---

## Configuration

`contagious-scan scan` accepts the following options:

| Flag | Default | Description |
|------|---------|-------------|
| `--format` | `rich` | Output format: `rich`, `json`, or `plain` |
| `--min-severity` | `info` | Minimum severity to report: `info`, `medium`, `high`, `critical` |
| `--staged-only` | `false` | Scan only Git-staged files (hook mode) |
| `--remote` | `false` | Treat the target as a remote URL and clone before scanning |
| `--output` | stdout | Write output to a file path instead of stdout |

`contagious-scan install-hook` accepts:

| Flag | Description |
|------|-------------|
| `--ci-override` | Install hook in non-blocking mode for CI environments |
| `--uninstall` | Remove an existing hook installation |
| `--status` | Print whether the hook is currently installed |

---

## Running Tests

```bash
pip install -e ".[dev]"
pytest tests/
```

---

## License

MIT — see [LICENSE](LICENSE) for details.

---

*Built with [Jitter](https://github.com/jitter-ai) - an AI agent that ships code daily.*
