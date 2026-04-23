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
| CI/CD poisoning | Suspicious `curl \| bash`, encoded payloads in GitHub Actions / GitLab CI |
| Network IOCs | Discord webhook exfiltration, Telegram bot C2, raw IP connections, suspicious TLDs |

---

## Installation

```bash
pip install contagious_scan
```

Or install from source:

```bash
git clone https://github.com/your-org/contagious_scan
cd contagious_scan
pip install -e .
```

---

## Quick Start

```bash
# Scan the current directory
contagious-scan scan .

# Scan a specific repository with JSON output
contagious-scan scan /path/to/repo --format json

# Scan only high-severity and above
contagious-scan scan . --min-severity high

# Scan a remote repository (clones it first)
contagious-scan scan https://github.com/some-org/suspicious-package --remote

# Install a pre-push hook to block compromised code
contagious-scan install-hook .

# Re-render a previously saved JSON result
contagious-scan report findings.json
```

---

## Commands

### `scan` — Audit a repository

```
contagious-scan scan [OPTIONS] [TARGET]
```

`TARGET` is a local directory path (default: `.`) or a remote Git URL when `--remote` is used.

| Option | Default | Description |
|---|---|---|
| `--format` | `rich` | Output format: `rich` (coloured table), `json`, or `plain` |
| `--min-severity` | `info` | Minimum severity to report: `critical`, `high`, `medium`, `info` |
| `--staged-only` | off | Only scan files staged in the Git index (pre-push hook mode) |
| `--remote` | off | Treat `TARGET` as a remote URL; clone before scanning |
| `--include-history` | off | Also scan files from commit history |
| `--history-depth` | `20` | Number of historical commits to inspect |
| `--include-untracked` | off | Also scan untracked (new) files |
| `--clone-depth` | `1` | Shallow clone depth for remote scans |
| `--branch` | default | Branch to scan or clone |
| `--output`, `-o` | — | Save JSON results to a file in addition to console output |
| `--ci-override` | off | Always exit `0` even when findings are present |
| `--skip-ext` | — | File extensions to skip (repeatable, e.g. `--skip-ext .md`) |
| `-v` / `--verbose` | off | Increase verbosity (`-v` = INFO, `-vv` = DEBUG) |

**Examples:**

```bash
# Full audit of a local repo, showing all severities
contagious-scan scan /path/to/repo --format rich

# CI pipeline: fail on high or above, output JSON
contagious-scan scan . --format json --min-severity high -o findings.json

# Scan only staged files (useful in hooks)
contagious-scan scan . --staged-only --min-severity critical

# Audit a remote npm package
contagious-scan scan https://github.com/org/suspicious-package --remote --format plain

# Scan with commit history inspection
contagious-scan scan . --include-history --history-depth 50

# Skip markdown and text files
contagious-scan scan . --skip-ext .md --skip-ext .txt
```

**Exit codes:**

| Code | Meaning |
|---|---|
| `0` | No findings at or above `--min-severity` |
| `1` | One or more findings at or above `--min-severity` |
| `2` | Scan error (invalid path, clone failure, etc.) |

---

### `install-hook` — Install the Git pre-push hook

```
contagious-scan install-hook [OPTIONS] [REPO_PATH]
```

Installs a `pre-push` hook script into `.git/hooks/` that runs `contagious-scan scan --staged-only` before each push. If critical-severity findings are detected, the push is blocked.

| Option | Default | Description |
|---|---|---|
| `--ci-override` | off | Install in non-blocking mode (scan runs but push is never blocked) |
| `--min-severity` | `critical` | Minimum severity that triggers a blocked push |
| `--force` | off | Overwrite any existing pre-push hook (creates a `.bak` backup) |
| `--no-backup` | off | Do not create a backup when overwriting |
| `--uninstall` | off | Remove the contagious_scan hook |
| `--status` | off | Show the current hook installation status |

**Examples:**

```bash
# Install the hook in the current repository
contagious-scan install-hook .

# Install for a specific repo, blocking on high severity and above
contagious-scan install-hook /path/to/repo --min-severity high

# Install in CI non-blocking mode
contagious-scan install-hook . --ci-override

# Overwrite an existing hook
contagious-scan install-hook . --force

# Check current status
contagious-scan install-hook . --status

# Remove the hook
contagious-scan install-hook . --uninstall
```

**How the hook works:**

1. Before each `git push`, the hook runs `contagious-scan scan . --staged-only --min-severity critical`.
2. If critical findings are detected (exit code `1`), the push is **blocked**.
3. If the scanner encounters an error (exit code `2`), the push is **allowed** (fail-open).
4. If no findings are detected, the push proceeds normally.

To bypass the hook in CI environments or when you need to push intentionally flagged content:

```bash
# Force push bypassing the hook
git push --no-verify

# Or install in non-blocking mode
contagious-scan install-hook . --ci-override
```

---

### `report` — Re-render a saved JSON result

```
contagious-scan report [OPTIONS] RESULTS_FILE
```

Re-renders a previously saved JSON scan result in any supported output format.

| Option | Default | Description |
|---|---|---|
| `--format` | `rich` | Output format: `rich`, `json`, or `plain` |
| `--min-severity` | `info` | Minimum severity to include |
| `--ci-override` | off | Always exit `0` |

**Examples:**

```bash
# View a saved result in the terminal
contagious-scan report findings.json

# Convert a saved result to plain text
contagious-scan report findings.json --format plain

# Filter to high and above
contagious-scan report findings.json --min-severity high

# Re-render as JSON with a different severity filter
contagious-scan report findings.json --format json --min-severity critical
```

---

## Pattern Coverage

### BeaverTail (JavaScript infostealer)

| Pattern ID | Description |
|---|---|
| `BT_JS_EVAL_ATOB` | `eval(atob(...))` payload execution |
| `BT_JS_KEYTAR_ABUSE` | `keytar` credential store access |
| `BT_JS_CRYPTO_WALLET_STEAL` | Cryptocurrency wallet file access (`wallet.dat`, etc.) |
| `BT_JS_BROWSER_COOKIE_STEAL` | Browser cookie database access |
| `BT_JS_BUFFER_FROM_B64` | `Buffer.from(..., 'base64')` payload decoding |
| `BT_JS_REQUIRE_DYNAMIC` | Dynamic `require()` with obfuscated paths |

### InvisibleFerret (Python backdoor / stager)

| Pattern ID | Description |
|---|---|
| `IF_PY_EXEC_B64DECODE` | `exec(base64.b64decode(...))` execution |
| `IF_PY_OS_SYSTEM_CURL_PIPE` | `os.system('curl ... \| bash')` |
| `IF_PY_BROWSER_DB_STEAL` | Browser `Login Data` / cookie theft |
| `IF_PY_SOCKET_REVERSE_SHELL` | Socket-based reverse shell pattern |
| `IF_PY_STAGER_URLOPEN` | `urllib.request.urlopen` payload fetch |

### Obfuscated loaders

| Pattern ID | Description |
|---|---|
| `OBF_BASE64_LONG_LITERAL` | Suspiciously long base64 string literal (>= 200 chars) |
| `OBF_CURL_PIPE_BASH` | `curl <url> \| bash` shell pipe pattern |
| `OBF_UNICODE_ESCAPE_SEQUENCE` | Dense Unicode escape sequence obfuscation |
| `OBF_SH_ENCODED_PAYLOAD` | `echo <b64> \| base64 -d \| bash` shell pattern |
| `OBF_HEX_ENCODED_BLOB` | Long hex-encoded payload blob |

### Lifecycle hook abuse

| Pattern ID | Description |
|---|---|
| `LH_NPM_POSTINSTALL_CURL` | `curl \| bash` in `postinstall` script |
| `LH_NPM_POSTINSTALL_WGET` | `wget` download in lifecycle script |
| `LH_NPM_POSTINSTALL_NODE_EVAL` | `node -e` eval in lifecycle script |
| `LH_NPM_B64_NODE_PAYLOAD` | Base64 payload in `node -e` lifecycle script |
| `LH_SETUP_PY_OS_SYSTEM` | `os.system()` call in `setup.py` |
| `LH_SETUP_PY_SUBPROCESS` | `subprocess` call in `setup.py` |
| `LH_SETUP_PY_URLLIB_FETCH` | `urllib.request` fetch in `setup.py` |
| `LH_SETUP_ATEXIT_EXEC` | `atexit.register()` payload trigger in `setup.py` |
| `LH_SETUP_CMDCLASS_RUN` | Custom `cmdclass` `run()` override in `setup.py` |

### CI/CD poisoning

| Pattern ID | Description |
|---|---|
| `CICD_GH_ACTIONS_CURL_PIPE` | `curl \| bash` in GitHub Actions workflow |
| `CICD_GH_ACTIONS_BASE64_EVAL` | Base64-encoded payload execution in workflow |
| `CICD_GH_ACTIONS_ENV_EXFIL` | Secret or environment variable exfiltration |

### Network IOCs

| Pattern ID | Description |
|---|---|
| `NET_SUSPICIOUS_TLD` | Connection to suspicious TLD (`.xyz`, `.top`, `.tk`, `.pw`, etc.) |
| `NET_RAW_IP_CONNECTION` | Direct connection to raw IP address |
| `NET_DISCORD_WEBHOOK_EXFIL` | Discord webhook used for data exfiltration |
| `NET_TELEGRAM_EXFIL` | Telegram Bot API used for C2 / exfiltration |

### Suspicious packages

| Pattern ID | Description |
|---|---|
| `PKG_NPM_KNOWN_MALICIOUS` | Known malicious npm package name (e.g. `dev-utils-pro`, `node-utils-extra`, `icons-packages`) |
| `PKG_PYPI_KNOWN_MALICIOUS` | Known malicious PyPI package name (e.g. `pycryptoenv`) |
| `PKG_NPM_TYPOSQUAT_REACT` | Typosquatting attack against `react` (e.g. `reaact`) |
| `PKG_HASH_MATCH` | File SHA-256 matches a known malicious payload hash |

---

## Python API

You can use `contagious_scan` programmatically:

```python
from contagious_scan.scanner import scan, ScanConfig, Scanner
from contagious_scan.reporter import Reporter, OutputFormat
from contagious_scan.detectors import detect_all, Finding

# Quick scan using the convenience function
result = scan("/path/to/repo", min_severity="high")
print(f"Found {result.total_findings} findings")
print(f"Has critical: {result.has_critical}")

# Detailed configuration
config = ScanConfig(
    target_path="/path/to/repo",
    min_severity="high",
    include_history=True,
    history_depth=50,
    skip_extensions=frozenset({".md", ".txt"}),
)
scanner = Scanner(config)
result = scanner.run()

# Render results
reporter = Reporter(OutputFormat.JSON, min_severity="high")
exit_code = reporter.render(result)

# Get results as a string
output = reporter.render_to_string(result)

# Serialise to dict / JSON
import json
data = result.to_dict()
print(json.dumps(data, indent=2))

# Run detectors directly on a string
findings = detect_all(content="eval(atob('SGVsbG8='));", file_path="loader.js")
for finding in findings:
    print(f"{finding.severity}: {finding.pattern_id} at line {finding.line_number}")
    print(f"  {finding.description}")
    print(f"  Matched: {finding.matched_text}")
    print(f"  Fix: {finding.remediation}")

# Scan a remote repository
result = scan(
    target=".",
    remote_url="https://github.com/org/suspicious-package",
    clone_depth=1,
    min_severity="critical",
)

# Add custom detectors
def my_detector(content: str, file_path: str) -> list[Finding]:
    findings = []
    if "my_secret_pattern" in content:
        findings.append(Finding(
            severity="high",
            file_path=file_path,
            line_number=1,
            pattern_id="CUSTOM_SECRET_PATTERN",
            description="Custom pattern detected",
            matched_text="my_secret_pattern",
            remediation="Remove the secret pattern.",
            tags=frozenset({"custom", "secret"}),
        ))
    return findings

result = scan(
    "/path/to/repo",
    extra_detectors=[my_detector],
    min_severity="info",
)
```

---

## Pre-push Hook Setup

The pre-push hook automatically scans staged files before every `git push` and blocks the push if critical findings are detected.

### Installation

```bash
# Install in the current repository (blocks on critical findings)
contagious-scan install-hook .

# Install with a lower severity threshold (blocks on high and above)
contagious-scan install-hook . --min-severity high

# Install in CI mode (scan runs but never blocks)
contagious-scan install-hook . --ci-override
```

### What gets installed

A `pre-push` shell script is written to `.git/hooks/pre-push` and made executable. The script:

1. Checks that `contagious-scan` is available in `PATH`.
2. Runs `contagious-scan scan . --staged-only --min-severity critical --format plain`.
3. Blocks the push (exit code `1`) if critical findings are detected.
4. Allows the push (exit code `0`) on scan errors (fail-open) or no findings.

### Override in CI

In CI pipelines where you do not want the hook to block pushes, use `--ci-override` at installation time:

```bash
contagious-scan install-hook . --ci-override
```

Or bypass the hook for a single push:

```bash
git push --no-verify
```

### Uninstall

```bash
contagious-scan install-hook . --uninstall
```

The uninstaller only removes hooks that were created by `contagious_scan` (identified by an internal marker comment). It will not remove third-party hooks.

---

## Output Formats

### `rich` (default)

Colour-coded terminal table with severity indicators, file locations, matched text, and remediation hints for critical findings.

```
╭─────────────────────────────────────────────────────────────────────────╮
│  contagious_scan  │  3 findings  │  🔴 1 CRITICAL  🟠 1 HIGH  🟡 1 MEDIUM  │  5 files scanned  │  0.12s  │
╰─────────────────────────────────────────────────────────────────────────╯

  Repository: /path/to/repo

╭───┬──────────┬────────────────────────┬──────┬───────────────────────┬──────────────────────────────────╮
│ # │ Severity │ File                   │ Line │ Pattern ID            │ Description                      │
├───┼──────────┼────────────────────────┼──────┼───────────────────────┼──────────────────────────────────┤
│ 1 │ CRITICAL │ loader.js              │ 1    │ BT_JS_EVAL_ATOB       │ BeaverTail: eval(atob(...))...   │
│ 2 │ HIGH     │ package.json           │ 5    │ LH_NPM_POSTINSTALL... │ Suspicious postinstall script... │
│ 3 │ MEDIUM   │ config.js              │ 3    │ NET_SUSPICIOUS_TLD    │ Connection to suspicious TLD...  │
╰───┴──────────┴────────────────────────┴──────┴───────────────────────┴──────────────────────────────────╯
```

### `json`

Machine-readable JSON output suitable for CI pipelines and programmatic processing:

```json
{
  "scan_timestamp": "2024-01-15T10:30:00Z",
  "repository": "/path/to/repo",
  "total_findings": 3,
  "severity_summary": {
    "critical": 1,
    "high": 1,
    "medium": 1,
    "info": 0
  },
  "findings": [
    {
      "severity": "critical",
      "file": "loader.js",
      "line": 1,
      "pattern_id": "BT_JS_EVAL_ATOB",
      "description": "BeaverTail: eval(atob(...)) payload execution pattern",
      "matched_text": "eval(atob('SGVsbG8gV29ybGQ='))",
      "remediation": "Remove the obfuscated eval call. Audit the decoded payload.",
      "tags": ["beavertail", "eval", "obfuscation", "rat"]
    }
  ],
  "scanned_files_count": 5,
  "skipped_files_count": 0,
  "errors": [],
  "elapsed_seconds": 0.12
}
```

### `plain`

Plain text output with no ANSI codes, suitable for logging and piping:

```
========================================================================
contagious_scan — Scan Report
========================================================================
Repository  : /path/to/repo
Timestamp   : 2024-01-15T10:30:00Z
Files scanned: 5
Elapsed     : 0.12s
Total findings (>= info): 3
  CRITICAL: 1
  HIGH: 1
  MEDIUM: 1

------------------------------------------------------------------------
#    SEVERITY   FILE                                LINE   PATTERN ID
------------------------------------------------------------------------
1    CRITICAL   loader.js                           1      BT_JS_EVAL_ATOB
...
```

---

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  contagious-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install contagious_scan
        run: pip install contagious_scan

      - name: Scan repository
        run: |
          contagious-scan scan . \
            --format json \
            --min-severity high \
            --output findings.json
        # Exit code 1 means findings were detected; fail the job

      - name: Upload findings
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: security-findings
          path: findings.json
```

### GitLab CI

```yaml
security-scan:
  image: python:3.11
  stage: test
  before_script:
    - pip install contagious_scan
  script:
    - contagious-scan scan . --format json --min-severity high -o findings.json
  artifacts:
    when: always
    paths:
      - findings.json
    reports:
      # Optionally convert to GitLab SAST format
      sast: findings.json
```

### Non-blocking CI scan (report only)

```bash
# Run the scan but always exit 0 (never fail the CI pipeline)
contagious-scan scan . --format json --ci-override -o findings.json
```

---

## Development

### Setup

```bash
git clone https://github.com/your-org/contagious_scan
cd contagious_scan
pip install -e ".[dev]"
```

### Running tests

```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run a specific test module
pytest tests/test_detectors.py -v

# Run with coverage
pytest --cov=contagious_scan --cov-report=term-missing
```

### Project structure

```
contagious_scan/
├── __init__.py          # Package init, version
├── cli.py               # Click CLI entry point (scan, install-hook, report)
├── scanner.py           # Scan orchestration pipeline
├── detectors.py         # Detector functions (RAT, obfuscation, hooks, etc.)
├── signatures.py        # IOC database: regex patterns, hashes, package names
├── git_utils.py         # Git helpers: staged files, history, remote clone
├── reporter.py          # Output rendering (rich / JSON / plain)
└── hook_installer.py    # Git pre-push hook installation

tests/
├── fixtures/
│   ├── malicious_package.json   # npm package with injected postinstall payload
│   └── malicious_setup.py       # Python setup.py with InvisibleFerret patterns
├── test_detectors.py    # Unit tests for each detector
├── test_scanner.py      # Integration tests against git repo fixtures
├── test_reporter.py     # Reporter output and exit code tests
├── test_hook_installer.py
├── test_git_utils.py
├── test_cli.py
└── test_signatures.py
```

---

## References

- [Trend Micro: "Contagious Interview" campaign analysis (2023–2024)](https://www.trendmicro.com/)
- [CISA advisories on DPRK developer-targeting campaigns](https://www.cisa.gov/)
- [BeaverTail and InvisibleFerret IOC reports](https://github.com/)
- [Unit 42: North Korean threat actor campaign](https://unit42.paloaltonetworks.com/)

---

## License

MIT — see [LICENSE](LICENSE) for details.

---

## Disclaimer

This tool is provided for **defensive security research and incident response** purposes only. The fixture files in `tests/fixtures/` contain intentionally malicious patterns for testing — do **not** execute them. The authors accept no liability for misuse.
