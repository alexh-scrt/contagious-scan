# contagious_scan

> A security CLI tool that audits local and remote Git repositories for indicators of **DPRK-style "Contagious Interview" supply chain attacks**.

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## Overview

`contagious_scan` detects malicious patterns attributed to North Korean threat actors operating the *Contagious Interview* campaign (tracked by Trend Micro and others). These attacks target software developers by distributing trojanised npm packages and Python libraries that install the **BeaverTail** infostealer and **InvisibleFerret** backdoor.

### What it detects

| Category | Examples |
|---|---|
| RAT payloads | BeaverTail JS loader, InvisibleFerret Python stager |
| Obfuscated loaders | Base64-chained `eval`/`exec`, hex-encoded shellcode blobs |
| Lifecycle hook abuse | Malicious `postinstall`, `prepare`, `preinstall` in `package.json` |
| Setup script abuse | `subprocess` / `os.system` calls inside `setup.py` / `pyproject.toml` |
| Tampered manifests | Hash mismatches, injected dependencies, suspicious package names |
| CI/CD poisoning | Suspicious `curl | bash`, encoded payloads in GitHub Actions / GitLab CI |

---

## Installation

```bash
pip install contagious_scan
```

Or for development:

```bash
git clone https://github.com/example/contagious_scan.git
cd contagious_scan
pip install -e ".[dev]"
```

---

## Usage

### Scan a local repository

```bash
# Scan the current directory (full working tree)
contagious-scan scan .

# Scan a specific path with JSON output
contagious-scan scan /path/to/repo --format json

# Scan only staged files (useful in hooks)
contagious-scan scan . --staged-only

# Fail on high severity or above
contagious-scan scan . --min-severity high
```

### Scan a remote repository

```bash
# Clone and scan a remote URL
contagious-scan scan https://github.com/example/suspicious-package --remote
```

### Install the Git pre-push hook

This blocks pushes when **critical**-severity findings are detected:

```bash
# Install into the current repo
contagious-scan install-hook .

# Install with CI override (exits 0 even on findings)
contagious-scan install-hook . --ci-override

# Install into a specific repo
contagious-scan install-hook /path/to/repo
```

The hook is written to `.git/hooks/pre-push` and is marked executable.

### Generate a report from a previous scan

```bash
# Re-render a saved JSON scan result
contagious-scan report findings.json --format rich
contagious-scan report findings.json --format plain
```

---

## Output Formats

### Rich terminal table (default)

```
╭──────────────────────────────────────────────────────────────────╮
│  contagious_scan  │  3 findings  │  1 CRITICAL  │  2 HIGH        │
╰──────────────────────────────────────────────────────────────────╯
┌──────────┬───────────────────────┬──────────┬───────────────────┐
│ Severity │ File                  │ Line     │ Description       │
├──────────┼───────────────────────┼──────────┼───────────────────┤
│ CRITICAL │ package.json          │ 8        │ Malicious post... │
│ HIGH     │ src/utils.js          │ 42       │ BeaverTail load.. │
│ HIGH     │ install.sh            │ 3        │ Obfuscated base.. │
└──────────┴───────────────────────┴──────────┴───────────────────┘
```

### JSON output

```json
{
  "scan_timestamp": "2024-01-15T10:30:00Z",
  "repository": "/path/to/repo",
  "total_findings": 3,
  "findings": [
    {
      "severity": "critical",
      "file": "package.json",
      "line": 8,
      "pattern_id": "NPM_POSTINSTALL_EXEC",
      "description": "Malicious postinstall hook executing remote payload",
      "matched_text": "curl https://...",
      "remediation": "Remove the postinstall script and audit all dependencies."
    }
  ]
}
```

---

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | No findings at or above the minimum severity |
| `1` | One or more findings at or above the minimum severity |
| `2` | Scan error (invalid path, git error, etc.) |

---

## Pattern Coverage

Detection rules are sourced from:

- Trend Micro's *Contagious Interview* research (2023–2024)
- CISA advisories on DPRK developer-targeting campaigns
- Public BeaverTail and InvisibleFerret IOC reports
- Community-contributed npm/PyPI malware patterns

Signatures are maintained in `contagious_scan/signatures.py` and include:

- **Regex patterns** for obfuscated JS/Python/Shell loaders
- **SHA-256 hashes** of known malicious payload files
- **Suspicious package names** matching typosquatting patterns
- **Dangerous API sequences** (`eval(atob(...))`, `exec(base64.b64decode(...))`, etc.)

---

## Pre-push Hook Details

After running `contagious-scan install-hook .`, the following script is written to `.git/hooks/pre-push`:

```bash
#!/usr/bin/env bash
# contagious_scan pre-push hook
# Blocks pushes when critical-severity indicators are detected.
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
contagious-scan scan "$REPO_ROOT" --staged-only --min-severity critical
EXIT_CODE=$?

if [ $EXIT_CODE -eq 1 ]; then
  echo "[contagious_scan] CRITICAL findings detected. Push blocked."
  echo "Run 'contagious-scan scan . --format rich' for details."
  exit 1
fi
```

Use `--ci-override` to suppress the blocking exit in automated pipelines.

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feat/new-detector`)
3. Add detector logic in `detectors.py` and signatures in `signatures.py`
4. Write tests in `tests/test_detectors.py`
5. Open a pull request

---

## License

MIT — see [LICENSE](LICENSE) for details.
