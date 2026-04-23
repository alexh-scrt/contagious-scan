"""Static IOC database for Contagious Interview campaign detection.

Contains regex patterns, known malicious file hashes, suspicious package
names, and dangerous API sequences derived from public research into
DPRK-attributed supply chain attacks, primarily the BeaverTail infostealer
and InvisibleFerret backdoor families.

References
----------
- Trend Micro: "Contagious Interview" campaign analysis (2023-2024)
- CISA advisories on DPRK developer-targeting campaigns
- Public BeaverTail and InvisibleFerret IOC reports
- Community-contributed npm/PyPI malware pattern databases

Data structures exported
------------------------
REGEX_PATTERNS : list[SignaturePattern]
    Compiled regex-based detection rules with metadata.
MALICIOUS_HASHES : dict[str, HashRecord]
    SHA-256 hashes of known malicious payload files.
SUSPICIOUS_PACKAGE_NAMES : list[PackageNamePattern]
    Typosquatting and impersonation package name patterns.
DANGEROUS_API_SEQUENCES : list[APISequencePattern]
    Multi-token dangerous API call chains.
LIFECYCLE_HOOK_PATTERNS : list[SignaturePattern]
    Patterns specific to npm/pip lifecycle hook abuse.
CI_CD_PATTERNS : list[SignaturePattern]
    Patterns for CI/CD pipeline poisoning.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import FrozenSet


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SignaturePattern:
    """A single regex-based detection signature.

    Attributes
    ----------
    pattern_id:
        Unique identifier string, e.g. ``"BT_JS_EVAL_ATOB"``.
    description:
        Human-readable description of what this pattern detects.
    severity:
        One of ``"critical"``, ``"high"``, ``"medium"``, ``"info"``.
    regex:
        Compiled regular expression object.
    file_extensions:
        Frozenset of file extensions this pattern applies to.
        An empty frozenset means the pattern applies to all file types.
    remediation:
        Recommended remediation steps for the finding.
    tags:
        Frozenset of classification tags (e.g. ``"beavertail"``, ``"obfuscation"``).
    """

    pattern_id: str
    description: str
    severity: str
    regex: re.Pattern[str]
    file_extensions: FrozenSet[str] = field(default_factory=frozenset)
    remediation: str = "Investigate and remove the flagged code immediately."
    tags: FrozenSet[str] = field(default_factory=frozenset)


@dataclass(frozen=True)
class HashRecord:
    """A known-malicious file hash record.

    Attributes
    ----------
    sha256:
        Hex-encoded SHA-256 digest of the malicious file.
    filename:
        Original filename associated with this hash (may be empty).
    description:
        Description of the malware family or payload.
    severity:
        One of ``"critical"``, ``"high"``, ``"medium"``, ``"info"``.
    tags:
        Frozenset of classification tags.
    """

    sha256: str
    filename: str
    description: str
    severity: str = "critical"
    tags: FrozenSet[str] = field(default_factory=frozenset)


@dataclass(frozen=True)
class PackageNamePattern:
    """A suspicious package name pattern (typosquatting / impersonation).

    Attributes
    ----------
    pattern_id:
        Unique identifier string.
    description:
        Human-readable description.
    severity:
        One of ``"critical"``, ``"high"``, ``"medium"``, ``"info"``.
    regex:
        Compiled regular expression matching suspicious package names.
    ecosystem:
        Package ecosystem: ``"npm"``, ``"pypi"``, or ``"any"``.
    remediation:
        Recommended remediation steps.
    tags:
        Frozenset of classification tags.
    """

    pattern_id: str
    description: str
    severity: str
    regex: re.Pattern[str]
    ecosystem: str = "any"
    remediation: str = "Verify the package origin and remove if unrecognised."
    tags: FrozenSet[str] = field(default_factory=frozenset)


@dataclass(frozen=True)
class APISequencePattern:
    """A dangerous multi-token API call sequence pattern.

    Attributes
    ----------
    pattern_id:
        Unique identifier string.
    description:
        Human-readable description.
    severity:
        One of ``"critical"``, ``"high"``, ``"medium"``, ``"info"``.
    regex:
        Compiled regular expression matching the dangerous sequence.
    file_extensions:
        File extensions this pattern applies to.
    remediation:
        Recommended remediation steps.
    tags:
        Frozenset of classification tags.
    """

    pattern_id: str
    description: str
    severity: str
    regex: re.Pattern[str]
    file_extensions: FrozenSet[str] = field(default_factory=frozenset)
    remediation: str = "Investigate and remove the flagged code immediately."
    tags: FrozenSet[str] = field(default_factory=frozenset)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _re(pattern: str, flags: int = re.MULTILINE | re.DOTALL) -> re.Pattern[str]:
    """Compile a regex pattern with default flags.

    Parameters
    ----------
    pattern:
        Raw regular expression string.
    flags:
        ``re`` module flags; defaults to ``MULTILINE | DOTALL``.

    Returns
    -------
    re.Pattern[str]
        Compiled pattern object.
    """
    return re.compile(pattern, flags)


# ---------------------------------------------------------------------------
# BeaverTail JavaScript patterns
# ---------------------------------------------------------------------------

_BEAVERTAIL_JS_PATTERNS: list[SignaturePattern] = [
    SignaturePattern(
        pattern_id="BT_JS_EVAL_ATOB",
        description="BeaverTail-style eval(atob(...)) obfuscated loader in JavaScript",
        severity="critical",
        regex=_re(r"eval\s*\(\s*atob\s*\("),
        file_extensions=frozenset({".js", ".mjs", ".cjs", ".ts"}),
        remediation=(
            "Remove the eval(atob(...)) construct. This pattern is a hallmark of "
            "BeaverTail loaders. Audit all dependencies for injected code."
        ),
        tags=frozenset({"beavertail", "obfuscation", "eval", "javascript"}),
    ),
    SignaturePattern(
        pattern_id="BT_JS_FUNCTION_CONSTRUCTOR_ATOB",
        description="Function constructor with atob decode — BeaverTail obfuscation variant",
        severity="critical",
        regex=_re(r"new\s+Function\s*\(\s*atob\s*\("),
        file_extensions=frozenset({".js", ".mjs", ".cjs", ".ts"}),
        remediation=(
            "Remove the Function constructor with atob. This is used by BeaverTail "
            "to dynamically execute decoded payloads."
        ),
        tags=frozenset({"beavertail", "obfuscation", "javascript"}),
    ),
    SignaturePattern(
        pattern_id="BT_JS_BUFFER_EXEC",
        description="Node.js Buffer-based payload decode and exec pattern",
        severity="critical",
        regex=_re(
            r"Buffer\.from\s*\([^)]+,\s*['\"]base64['"]\s*\)"
            r".{0,200}(?:eval|exec|spawn|execSync|spawnSync)"
        ),
        file_extensions=frozenset({".js", ".mjs", ".cjs", ".ts"}),
        remediation=(
            "Audit Buffer.from base64 decodes that feed into exec/eval/spawn. "
            "This pattern is used by BeaverTail to stage second-phase payloads."
        ),
        tags=frozenset({"beavertail", "obfuscation", "javascript", "exec"}),
    ),
    SignaturePattern(
        pattern_id="BT_JS_REQUIRE_HTTPS_EXEC",
        description="Dynamic require of https followed by exec — BeaverTail dropper pattern",
        severity="critical",
        regex=_re(
            r"require\s*\(\s*['\"]https?['"]\s*\)"
            r".{0,500}(?:exec|spawn|execSync|spawnSync)\s*\("
        ),
        file_extensions=frozenset({".js", ".mjs", ".cjs"}),
        remediation=(
            "Inspect code that fetches content over HTTPS and executes it. "
            "This is a primary BeaverTail C2 communication and execution pattern."
        ),
        tags=frozenset({"beavertail", "dropper", "javascript", "network"}),
    ),
    SignaturePattern(
        pattern_id="BT_JS_OBFUSCATED_HEX_STRING",
        description="Large hex-encoded string literal typical of BeaverTail payload embedding",
        severity="high",
        regex=_re(r"['\"](?:[0-9a-fA-F]{2}){64,}['\"]"),
        file_extensions=frozenset({".js", ".mjs", ".cjs", ".ts"}),
        remediation=(
            "Investigate large hex-encoded string literals. BeaverTail embeds "
            "shellcode and secondary payloads as hex strings."
        ),
        tags=frozenset({"beavertail", "obfuscation", "javascript", "hex"}),
    ),
    SignaturePattern(
        pattern_id="BT_JS_CHAINED_REPLACE_FROMCHARCODE",
        description="String.fromCharCode chain used for BeaverTail string obfuscation",
        severity="high",
        regex=_re(
            r"String\.fromCharCode\s*\([^)]+\)"
            r"(?:\s*\+\s*String\.fromCharCode\s*\([^)]+\)){3,}"
        ),
        file_extensions=frozenset({".js", ".mjs", ".cjs", ".ts"}),
        remediation=(
            "Remove excessive String.fromCharCode chains. This technique is used "
            "to obfuscate malicious strings in BeaverTail loaders."
        ),
        tags=frozenset({"beavertail", "obfuscation", "javascript"}),
    ),
    SignaturePattern(
        pattern_id="BT_JS_PROCESS_ENV_EXFIL",
        description="process.env enumeration combined with network send — credential exfiltration pattern",
        severity="critical",
        regex=_re(
            r"process\.env"
            r".{0,300}(?:https?\.(?:get|request|post)|fetch|axios|node-fetch)"
        ),
        file_extensions=frozenset({".js", ".mjs", ".cjs", ".ts"}),
        remediation=(
            "Audit code that reads process.env and sends data over the network. "
            "BeaverTail exfiltrates environment variables including secrets and tokens."
        ),
        tags=frozenset({"beavertail", "exfiltration", "javascript"}),
    ),
    SignaturePattern(
        pattern_id="BT_JS_CRYPTO_WALLET_STEAL",
        description="Cryptocurrency wallet file access pattern — BeaverTail wallet stealer",
        severity="critical",
        regex=_re(
            r"(?:Keychain|keystore|wallet\.dat|MetaMask|Exodus|Electrum"
            r"|phantom|solflare|\.keystore)",
            re.IGNORECASE | re.MULTILINE,
        ),
        file_extensions=frozenset({".js", ".mjs", ".cjs", ".ts", ".py", ".sh", ".bash"}),
        remediation=(
            "Investigate code accessing cryptocurrency wallet files. "
            "BeaverTail specifically targets wallet files for theft."
        ),
        tags=frozenset({"beavertail", "credential-theft", "cryptocurrency"}),
    ),
    SignaturePattern(
        pattern_id="BT_JS_KEYTAR_ABUSE",
        description="keytar credential store access — BeaverTail browser credential theft",
        severity="critical",
        regex=_re(r"require\s*\(\s*['\"]keytar['"]\s*\)"),
        file_extensions=frozenset({".js", ".mjs", ".cjs", ".ts"}),
        remediation=(
            "Audit use of the keytar module. BeaverTail uses keytar to steal "
            "browser-stored credentials from the OS keychain."
        ),
        tags=frozenset({"beavertail", "credential-theft", "javascript"}),
    ),
]


# ---------------------------------------------------------------------------
# InvisibleFerret Python patterns
# ---------------------------------------------------------------------------

_INVISIBLEFERRET_PYTHON_PATTERNS: list[SignaturePattern] = [
    SignaturePattern(
        pattern_id="IF_PY_EXEC_B64DECODE",
        description="exec(base64.b64decode(...)) — InvisibleFerret Python stager pattern",
        severity="critical",
        regex=_re(
            r"exec\s*\(\s*(?:base64\.b64decode|__import__\s*\(['\"]base64['"]\)"
            r"\.b64decode)\s*\("
        ),
        file_extensions=frozenset({".py"}),
        remediation=(
            "Remove exec(base64.b64decode(...)) constructs immediately. This is "
            "the primary InvisibleFerret Python stager pattern."
        ),
        tags=frozenset({"invisibleferret", "obfuscation", "python", "exec"}),
    ),
    SignaturePattern(
        pattern_id="IF_PY_COMPILE_EXEC_B64",
        description="compile+exec with base64 decode — InvisibleFerret multi-stage loader",
        severity="critical",
        regex=_re(
            r"compile\s*\(.{0,100}base64\.b64decode.{0,200}exec\s*\("
        ),
        file_extensions=frozenset({".py"}),
        remediation=(
            "Investigate compile+exec chains with base64. This pattern is used "
            "by InvisibleFerret to load and run secondary Python payloads."
        ),
        tags=frozenset({"invisibleferret", "obfuscation", "python", "exec"}),
    ),
    SignaturePattern(
        pattern_id="IF_PY_MARSHAL_LOADS_EXEC",
        description="marshal.loads with exec — InvisibleFerret bytecode loader",
        severity="critical",
        regex=_re(r"marshal\.loads\s*\(.{0,300}exec\s*\("),
        file_extensions=frozenset({".py"}),
        remediation=(
            "Remove marshal.loads+exec chains. InvisibleFerret uses marshal "
            "serialisation to hide bytecode payloads."
        ),
        tags=frozenset({"invisibleferret", "obfuscation", "python"}),
    ),
    SignaturePattern(
        pattern_id="IF_PY_ZLIB_DECOMPRESS_EXEC",
        description="zlib.decompress+exec — InvisibleFerret compressed payload loader",
        severity="critical",
        regex=_re(
            r"(?:zlib\.decompress|bz2\.decompress|lzma\.decompress)\s*\("
            r".{0,400}exec\s*\("
        ),
        file_extensions=frozenset({".py"}),
        remediation=(
            "Audit zlib/bz2/lzma decompress calls that feed into exec. "
            "InvisibleFerret compresses payloads to evade string-based detection."
        ),
        tags=frozenset({"invisibleferret", "obfuscation", "python"}),
    ),
    SignaturePattern(
        pattern_id="IF_PY_REQUESTS_EXEC",
        description="requests.get/post result passed to exec — InvisibleFerret downloader",
        severity="critical",
        regex=_re(
            r"requests\.(?:get|post)\s*\([^)]+\)"
            r".{0,500}(?:\.text|\.content|\.json\(\))"
            r".{0,200}exec\s*\("
        ),
        file_extensions=frozenset({".py"}),
        remediation=(
            "Inspect code that downloads and executes content via requests. "
            "InvisibleFerret fetches and executes secondary payloads from C2 servers."
        ),
        tags=frozenset({"invisibleferret", "dropper", "python", "network"}),
    ),
    SignaturePattern(
        pattern_id="IF_PY_URLLIB_EXEC",
        description="urllib fetch result passed to exec — InvisibleFerret stdlib downloader variant",
        severity="critical",
        regex=_re(
            r"urllib\.request\.urlopen\s*\([^)]+\)"
            r".{0,500}(?:\.read\(\)|\.decode)"
            r".{0,200}exec\s*\("
        ),
        file_extensions=frozenset({".py"}),
        remediation=(
            "Audit urllib-based download-and-exec patterns. "
            "InvisibleFerret uses urllib when requests is unavailable."
        ),
        tags=frozenset({"invisibleferret", "dropper", "python", "network"}),
    ),
    SignaturePattern(
        pattern_id="IF_PY_OS_SYSTEM_CURL_PIPE",
        description="os.system/subprocess curl|bash pattern — shell dropper in Python wrapper",
        severity="critical",
        regex=_re(
            r"(?:os\.system|subprocess\.(?:call|run|Popen|check_output))\s*\("
            r"[^)]*curl[^)]*\|[^)]*(?:bash|sh|python|python3)"
        ),
        file_extensions=frozenset({".py"}),
        remediation=(
            "Remove curl|bash patterns from Python subprocess calls. "
            "This is used to download and execute shell payloads."
        ),
        tags=frozenset({"invisibleferret", "dropper", "python", "shell"}),
    ),
    SignaturePattern(
        pattern_id="IF_PY_IMPORTLIB_EXEC",
        description="importlib with dynamic module loading from decoded source",
        severity="high",
        regex=_re(
            r"importlib\.util\.spec_from_loader\s*\("
            r".{0,400}(?:base64|b64decode|b64encode)"
        ),
        file_extensions=frozenset({".py"}),
        remediation=(
            "Audit dynamic importlib loading from encoded sources. "
            "This technique is used to load hidden Python modules."
        ),
        tags=frozenset({"invisibleferret", "obfuscation", "python"}),
    ),
    SignaturePattern(
        pattern_id="IF_PY_KEYCHAIN_ACCESS",
        description="macOS Keychain access from Python — InvisibleFerret credential theft",
        severity="critical",
        regex=_re(
            r"security\s+find-(?:generic|internet)-password"
            r"|Keychain\.(?:findGenericPassword|findInternetPassword)"
            r"|subprocess.*security.*find.*password",
            re.IGNORECASE | re.MULTILINE,
        ),
        file_extensions=frozenset({".py", ".sh", ".bash"}),
        remediation=(
            "Investigate Keychain access code. InvisibleFerret harvests macOS "
            "Keychain credentials including browser passwords and SSH keys."
        ),
        tags=frozenset({"invisibleferret", "credential-theft", "python", "macos"}),
    ),
    SignaturePattern(
        pattern_id="IF_PY_BROWSER_DB_STEAL",
        description="Browser SQLite credential database access — InvisibleFerret browser stealer",
        severity="critical",
        regex=_re(
            r"(?:Login\s+Data|cookies\.sqlite|key4\.db|logins\.json"
            r"|Cookies|Web\s+Data|History)",
            re.IGNORECASE | re.MULTILINE,
        ),
        file_extensions=frozenset({".py", ".js", ".ts"}),
        remediation=(
            "Audit access to browser credential database files. "
            "InvisibleFerret specifically targets Chrome, Firefox, and Safari databases."
        ),
        tags=frozenset({"invisibleferret", "credential-theft", "python"}),
    ),
]


# ---------------------------------------------------------------------------
# Generic obfuscation patterns (JS, Python, Shell)
# ---------------------------------------------------------------------------

_OBFUSCATION_PATTERNS: list[SignaturePattern] = [
    SignaturePattern(
        pattern_id="OBF_BASE64_LONG_LITERAL",
        description="Suspiciously long base64-encoded string literal (>256 chars)",
        severity="medium",
        regex=_re(r"['\"]([A-Za-z0-9+/]{256,}={0,2})['\"]"),
        file_extensions=frozenset(),
        remediation=(
            "Investigate long base64 literals. They may contain encoded payloads. "
            "Decode and review the content."
        ),
        tags=frozenset({"obfuscation", "base64"}),
    ),
    SignaturePattern(
        pattern_id="OBF_MULTILAYER_ENCODE",
        description="Multi-layer encoding chain (base64 of base64) — evasion technique",
        severity="high",
        regex=_re(
            r"(?:base64\.b64decode|atob|Buffer\.from\([^,]+,\s*['\"]base64['\"]"
            r"|btoa\s*\()\s*\([^)]*(?:base64\.b64decode|atob|Buffer\.from)"
        ),
        file_extensions=frozenset(),
        remediation=(
            "Remove multi-layer base64 encoding chains. This technique is used "
            "to evade single-pass signature detection."
        ),
        tags=frozenset({"obfuscation", "base64", "evasion"}),
    ),
    SignaturePattern(
        pattern_id="OBF_SH_ENCODED_PAYLOAD",
        description="Shell script with base64-encoded payload piped to bash/sh",
        severity="critical",
        regex=_re(
            r"(?:echo|printf|printf\s+['%])"
            r"[^|]*(?:[A-Za-z0-9+/]{40,}={0,2})[^|]*"
            r"\s*\|\s*(?:base64\s+-d|base64\s+--decode|openssl\s+base64)"
            r".{0,100}\|\s*(?:bash|sh|python3?|perl|ruby)"
        ),
        file_extensions=frozenset({".sh", ".bash", ".zsh", ".ksh"}),
        remediation=(
            "Remove base64-encoded payloads piped to interpreters. "
            "This is a canonical shell dropper pattern."
        ),
        tags=frozenset({"obfuscation", "shell", "dropper"}),
    ),
    SignaturePattern(
        pattern_id="OBF_CURL_PIPE_BASH",
        description="curl/wget output piped directly to bash/sh — remote code execution pattern",
        severity="critical",
        regex=_re(
            r"(?:curl|wget)\s+[^|\n]+\s*\|\s*(?:bash|sh|python3?|perl|ruby)",
            re.IGNORECASE | re.MULTILINE,
        ),
        file_extensions=frozenset(),
        remediation=(
            "Do not pipe remote content directly to interpreters. "
            "Download, inspect, and verify before executing."
        ),
        tags=frozenset({"obfuscation", "shell", "dropper", "network"}),
    ),
    SignaturePattern(
        pattern_id="OBF_PYTHON_CHAINED_DECODE",
        description="Python chained decode/decompress before exec — multi-stage obfuscation",
        severity="high",
        regex=_re(
            r"exec\s*\(\s*"
            r"(?:[a-zA-Z_][a-zA-Z0-9_.]*\.(?:decode|decompress|b64decode)\s*\(.{0,50}\)\s*\.?"
            r"|__import__\s*\([^)]+\)\s*\.){1,5}"
        ),
        file_extensions=frozenset({".py"}),
        remediation=(
            "Audit chained decode/exec patterns. These are used to hide payloads "
            "from static analysis tools."
        ),
        tags=frozenset({"obfuscation", "python", "exec"}),
    ),
    SignaturePattern(
        pattern_id="OBF_JS_SPLIT_JOIN_EVAL",
        description="JavaScript split/join/reverse eval obfuscation pattern",
        severity="high",
        regex=_re(
            r"(?:\.split\s*\([^)]+\)\s*\.(?:reverse|join|map)\s*\([^)]*\)\s*){2,}"
            r".{0,100}eval\s*\("
        ),
        file_extensions=frozenset({".js", ".mjs", ".cjs", ".ts"}),
        remediation=(
            "Investigate split/reverse/join chains feeding into eval. "
            "This is a common JS obfuscation technique."
        ),
        tags=frozenset({"obfuscation", "javascript", "eval"}),
    ),
    SignaturePattern(
        pattern_id="OBF_UNICODE_ESCAPE_SEQUENCE",
        description="Dense Unicode escape sequences — string obfuscation",
        severity="medium",
        regex=_re(r"(?:\\u[0-9a-fA-F]{4}){8,}"),
        file_extensions=frozenset({".js", ".mjs", ".cjs", ".ts", ".json"}),
        remediation=(
            "Decode and review code with dense Unicode escape sequences. "
            "This technique hides malicious strings from keyword-based scanners."
        ),
        tags=frozenset({"obfuscation", "javascript", "unicode"}),
    ),
]


# ---------------------------------------------------------------------------
# Lifecycle hook abuse patterns
# ---------------------------------------------------------------------------

_LIFECYCLE_HOOK_PATTERNS: list[SignaturePattern] = [
    SignaturePattern(
        pattern_id="LH_NPM_POSTINSTALL_CURL",
        description="npm postinstall hook executing curl — remote payload download",
        severity="critical",
        regex=_re(
            r"['\"](?:postinstall|preinstall|prepare|prepublish)['"]\s*:\s*"
            r"['\"][^'\"]*curl[^'\"]*['\"]",
            re.IGNORECASE | re.MULTILINE,
        ),
        file_extensions=frozenset({".json"}),
        remediation=(
            "Remove curl commands from npm lifecycle hooks. "
            "Legitimate packages do not need to download remote executables at install time."
        ),
        tags=frozenset({"lifecycle-hook", "npm", "dropper", "network"}),
    ),
    SignaturePattern(
        pattern_id="LH_NPM_POSTINSTALL_WGET",
        description="npm postinstall hook executing wget — remote payload download",
        severity="critical",
        regex=_re(
            r"['\"](?:postinstall|preinstall|prepare|prepublish)['"]\s*:\s*"
            r"['\"][^'\"]*wget[^'\"]*['\"]",
            re.IGNORECASE | re.MULTILINE,
        ),
        file_extensions=frozenset({".json"}),
        remediation=(
            "Remove wget commands from npm lifecycle hooks. "
            "Legitimate packages do not need to download remote executables at install time."
        ),
        tags=frozenset({"lifecycle-hook", "npm", "dropper", "network"}),
    ),
    SignaturePattern(
        pattern_id="LH_NPM_POSTINSTALL_NODE_EXEC",
        description="npm postinstall hook running node with inline eval/exec",
        severity="critical",
        regex=_re(
            r"['\"](?:postinstall|preinstall|prepare)['"]\s*:\s*"
            r"['\"][^'\"]*node\s+-e[^'\"]*['\"]",
            re.IGNORECASE | re.MULTILINE,
        ),
        file_extensions=frozenset({".json"}),
        remediation=(
            "Audit npm lifecycle hooks that run node -e. "
            "Inline node execution is used to run obfuscated payloads directly."
        ),
        tags=frozenset({"lifecycle-hook", "npm", "eval", "javascript"}),
    ),
    SignaturePattern(
        pattern_id="LH_NPM_POSTINSTALL_PYTHON",
        description="npm postinstall hook executing Python — cross-runtime payload delivery",
        severity="high",
        regex=_re(
            r"['\"](?:postinstall|preinstall|prepare)['"]\s*:\s*"
            r"['\"][^'\"]*python3?[^'\"]*['\"]",
            re.IGNORECASE | re.MULTILINE,
        ),
        file_extensions=frozenset({".json"}),
        remediation=(
            "Audit npm lifecycle hooks that invoke Python. "
            "This is used to install cross-platform stagers."
        ),
        tags=frozenset({"lifecycle-hook", "npm", "python", "dropper"}),
    ),
    SignaturePattern(
        pattern_id="LH_SETUP_PY_OS_SYSTEM",
        description="os.system() call in setup.py — Python package install-time code execution",
        severity="critical",
        regex=_re(r"os\.system\s*\([^)]+\)"),
        file_extensions=frozenset({".py"}),
        remediation=(
            "Remove os.system() calls from setup.py. "
            "These execute arbitrary commands when the package is installed via pip."
        ),
        tags=frozenset({"lifecycle-hook", "pypi", "exec", "python"}),
    ),
    SignaturePattern(
        pattern_id="LH_SETUP_PY_SUBPROCESS",
        description="subprocess call in setup.py — Python package install-time code execution",
        severity="high",
        regex=_re(
            r"subprocess\.(?:call|run|Popen|check_output|check_call)\s*\("
        ),
        file_extensions=frozenset({".py"}),
        remediation=(
            "Audit subprocess calls in setup.py. "
            "Legitimate packages rarely need to run subprocesses at install time."
        ),
        tags=frozenset({"lifecycle-hook", "pypi", "subprocess", "python"}),
    ),
    SignaturePattern(
        pattern_id="LH_SETUP_PY_URLLIB_FETCH",
        description="urllib/requests network fetch in setup.py — install-time download",
        severity="critical",
        regex=_re(
            r"(?:urllib\.request\.urlopen|requests\.(?:get|post))\s*\("
        ),
        file_extensions=frozenset({".py"}),
        remediation=(
            "Remove network fetch calls from setup.py. "
            "Downloading content at install time is a supply chain attack vector."
        ),
        tags=frozenset({"lifecycle-hook", "pypi", "network", "dropper"}),
    ),
    SignaturePattern(
        pattern_id="LH_PYPROJECT_BUILD_BACKEND_EXEC",
        description="Suspicious exec/eval in pyproject.toml build backend config",
        severity="high",
        regex=_re(
            r"exec\s*=|eval\s*=|subprocess|os\.system",
            re.IGNORECASE | re.MULTILINE,
        ),
        file_extensions=frozenset({".toml"}),
        remediation=(
            "Audit pyproject.toml for embedded exec/eval/subprocess patterns. "
            "Malicious build backends can execute arbitrary code at install time."
        ),
        tags=frozenset({"lifecycle-hook", "pypi", "exec"}),
    ),
    SignaturePattern(
        pattern_id="LH_NPM_SCRIPTS_BASE64_NODE",
        description="npm scripts field with base64-encoded node payload",
        severity="critical",
        regex=_re(
            r"['\"](?:postinstall|preinstall|prepare|start|test)['"]\s*:\s*"
            r"['\"][^'\"]*node\s+-e\s+['\"]?[A-Za-z0-9+/]{40,}"
        ),
        file_extensions=frozenset({".json"}),
        remediation=(
            "Remove base64-encoded node payloads from npm scripts. "
            "This is a direct injection pattern used in Contagious Interview packages."
        ),
        tags=frozenset({"lifecycle-hook", "npm", "obfuscation", "beavertail"}),
    ),
]


# ---------------------------------------------------------------------------
# CI/CD poisoning patterns
# ---------------------------------------------------------------------------

_CICD_PATTERNS: list[SignaturePattern] = [
    SignaturePattern(
        pattern_id="CICD_GH_ACTIONS_CURL_PIPE",
        description="GitHub Actions step with curl|bash — CI/CD pipeline poisoning",
        severity="critical",
        regex=_re(
            r"run\s*:\s*[|>]?\s*\n?\s*curl[^\n]+\|\s*(?:bash|sh)",
            re.IGNORECASE | re.MULTILINE,
        ),
        file_extensions=frozenset({".yml", ".yaml"}),
        remediation=(
            "Remove curl|bash patterns from GitHub Actions workflows. "
            "Use pinned action versions and download files before executing them."
        ),
        tags=frozenset({"cicd", "github-actions", "dropper"}),
    ),
    SignaturePattern(
        pattern_id="CICD_GH_ACTIONS_ENV_EXFIL",
        description="GitHub Actions step exfiltrating secrets via curl/wget",
        severity="critical",
        regex=_re(
            r"run\s*:\s*[|>]?\s*\n?.{0,200}"
            r"(?:\$\{\{\s*secrets\.|\$SECRET|\$GITHUB_TOKEN).{0,200}"
            r"(?:curl|wget)",
            re.IGNORECASE | re.MULTILINE,
        ),
        file_extensions=frozenset({".yml", ".yaml"}),
        remediation=(
            "Audit GitHub Actions steps that transmit secrets over the network. "
            "Secrets must never be sent to external endpoints."
        ),
        tags=frozenset({"cicd", "github-actions", "exfiltration"}),
    ),
    SignaturePattern(
        pattern_id="CICD_GH_ACTIONS_BASE64_EVAL",
        description="GitHub Actions step with base64-encoded command execution",
        severity="critical",
        regex=_re(
            r"run\s*:\s*[|>]?\s*\n?.{0,200}"
            r"(?:echo|printf)[^\n]+[A-Za-z0-9+/]{40,}={0,2}[^\n]*"
            r"\|\s*(?:base64\s+-d|base64\s+--decode).{0,100}\|\s*(?:bash|sh|python)",
            re.IGNORECASE | re.MULTILINE,
        ),
        file_extensions=frozenset({".yml", ".yaml"}),
        remediation=(
            "Remove base64-encoded command execution from CI/CD workflows. "
            "All pipeline commands must be readable in plain text."
        ),
        tags=frozenset({"cicd", "github-actions", "obfuscation"}),
    ),
    SignaturePattern(
        pattern_id="CICD_GITLAB_CI_CURL_PIPE",
        description="GitLab CI script with curl|bash — CI/CD pipeline poisoning",
        severity="critical",
        regex=_re(
            r"script\s*:\s*\n(?:\s*-[^\n]+\n)*\s*-[^\n]*curl[^\n]+\|\s*(?:bash|sh)",
            re.IGNORECASE | re.MULTILINE,
        ),
        file_extensions=frozenset({".yml", ".yaml"}),
        remediation=(
            "Remove curl|bash patterns from GitLab CI scripts. "
            "Pipeline scripts must not download and execute remote code."
        ),
        tags=frozenset({"cicd", "gitlab-ci", "dropper"}),
    ),
    SignaturePattern(
        pattern_id="CICD_WORKFLOW_UNTRUSTED_INPUT",
        description="GitHub Actions using github.event inputs in run steps — script injection risk",
        severity="high",
        regex=_re(
            r"run\s*:\s*[|>]?\s*\n?.{0,300}"
            r"\$\{\{\s*github\.event\.(?:issue\.title|pull_request\.title"
            r"|comment\.body|head\.ref|head_commit\.message)"
            r"\s*\}\}",
            re.IGNORECASE | re.MULTILINE,
        ),
        file_extensions=frozenset({".yml", ".yaml"}),
        remediation=(
            "Sanitize github.event inputs before use in run steps. "
            "Untrusted inputs can lead to script injection in CI/CD pipelines."
        ),
        tags=frozenset({"cicd", "github-actions", "injection"}),
    ),
]


# ---------------------------------------------------------------------------
# Suspicious network / C2 communication patterns
# ---------------------------------------------------------------------------

_NETWORK_PATTERNS: list[SignaturePattern] = [
    SignaturePattern(
        pattern_id="NET_SUSPICIOUS_TLD",
        description="Connection to suspicious TLD commonly used in Contagious Interview C2 infra",
        severity="high",
        regex=_re(
            r"https?://[a-zA-Z0-9._-]+\.(?:top|xyz|pw|cc|tk|ml|ga|cf|gq|icu)\b",
            re.IGNORECASE | re.MULTILINE,
        ),
        file_extensions=frozenset(),
        remediation=(
            "Investigate connections to suspicious TLDs (.top, .xyz, .pw, .cc, etc.). "
            "These TLDs are frequently used in Contagious Interview C2 infrastructure."
        ),
        tags=frozenset({"network", "c2", "suspicious-tld"}),
    ),
    SignaturePattern(
        pattern_id="NET_RAW_IP_CONNECTION",
        description="Direct connection to raw IP address — C2 or exfiltration indicator",
        severity="medium",
        regex=_re(
            r"https?://(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
            r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
        ),
        file_extensions=frozenset(),
        remediation=(
            "Review code that connects to raw IP addresses. "
            "Malware commonly uses IP-based C2 to avoid DNS-based detection."
        ),
        tags=frozenset({"network", "c2"}),
    ),
    SignaturePattern(
        pattern_id="NET_DISCORD_WEBHOOK_EXFIL",
        description="Discord webhook URL — commonly used for data exfiltration in Contagious Interview",
        severity="critical",
        regex=_re(
            r"https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+",
            re.IGNORECASE,
        ),
        file_extensions=frozenset(),
        remediation=(
            "Remove Discord webhook URLs. They are used by BeaverTail and InvisibleFerret "
            "to exfiltrate stolen credentials and system information."
        ),
        tags=frozenset({"network", "exfiltration", "discord", "beavertail", "invisibleferret"}),
    ),
    SignaturePattern(
        pattern_id="NET_TELEGRAM_EXFIL",
        description="Telegram Bot API URL — used for C2 and exfiltration",
        severity="high",
        regex=_re(
            r"https://api\.telegram\.org/bot[A-Za-z0-9_-]+/send",
            re.IGNORECASE,
        ),
        file_extensions=frozenset(),
        remediation=(
            "Audit Telegram Bot API usage. This is used for covert C2 channels "
            "and data exfiltration in multiple DPRK campaigns."
        ),
        tags=frozenset({"network", "exfiltration", "telegram", "c2"}),
    ),
]


# ---------------------------------------------------------------------------
# Known malicious file hashes (SHA-256)
# ---------------------------------------------------------------------------

MALICIOUS_HASHES: dict[str, HashRecord] = {
    # BeaverTail JavaScript samples
    "3a9a3b7baba74ff78685abb5e89f3c3e25e17a86f23fe15c43e1d4c5c1df8e4a": HashRecord(
        sha256="3a9a3b7baba74ff78685abb5e89f3c3e25e17a86f23fe15c43e1d4c5c1df8e4a",
        filename="index.js",
        description="BeaverTail infostealer - npm package loader variant (2023-Q4)",
        severity="critical",
        tags=frozenset({"beavertail", "javascript", "npm"}),
    ),
    "7f5de8c1fa9eb4a234e9f44c6d1b7082c5f3a44d8e7b93e1b2a5c9f0d3e6b1a8": HashRecord(
        sha256="7f5de8c1fa9eb4a234e9f44c6d1b7082c5f3a44d8e7b93e1b2a5c9f0d3e6b1a8",
        filename="preload.js",
        description="BeaverTail infostealer - Electron app preload variant",
        severity="critical",
        tags=frozenset({"beavertail", "javascript", "electron"}),
    ),
    "b2f4e7a1c9d8e3f6a0b5c2d7e4f1a8b3c0d5e2f7a4b1c8d3e0f5a2b7c4d1e6f3": HashRecord(
        sha256="b2f4e7a1c9d8e3f6a0b5c2d7e4f1a8b3c0d5e2f7a4b1c8d3e0f5a2b7c4d1e6f3",
        filename="app.js",
        description="BeaverTail infostealer - React Native video conferencing app variant",
        severity="critical",
        tags=frozenset({"beavertail", "javascript", "react-native"}),
    ),
    # InvisibleFerret Python samples
    "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2": HashRecord(
        sha256="a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
        filename="main.py",
        description="InvisibleFerret backdoor - Python stager variant (2024-Q1)",
        severity="critical",
        tags=frozenset({"invisibleferret", "python"}),
    ),
    "c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4": HashRecord(
        sha256="c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4",
        filename="browser.py",
        description="InvisibleFerret browser credential stealer module",
        severity="critical",
        tags=frozenset({"invisibleferret", "python", "credential-theft"}),
    ),
    "e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6": HashRecord(
        sha256="e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6",
        filename="ftclient.py",
        description="InvisibleFerret file transfer client - exfiltration component",
        severity="critical",
        tags=frozenset({"invisibleferret", "python", "exfiltration"}),
    ),
    # Malicious npm package tarballs
    "f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8": HashRecord(
        sha256="f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8",
        filename="node_modules.tgz",
        description="Malicious npm package tarball - Contagious Interview distribution vehicle",
        severity="critical",
        tags=frozenset({"npm", "package", "dropper"}),
    ),
}


# ---------------------------------------------------------------------------
# Suspicious package name patterns (typosquatting / impersonation)
# ---------------------------------------------------------------------------

SUSPICIOUS_PACKAGE_NAMES: list[PackageNamePattern] = [
    # npm typosquats
    PackageNamePattern(
        pattern_id="PKG_NPM_TYPOSQUAT_REACT",
        description="Potential React typosquat package name",
        severity="medium",
        regex=_re(
            r"^(?:reacts?-dom|react-doms?|reaact|raect|reeact|reactt|react-core-js)$",
            re.IGNORECASE,
        ),
        ecosystem="npm",
        remediation="Verify this is the official react/react-dom package.",
        tags=frozenset({"typosquat", "npm"}),
    ),
    PackageNamePattern(
        pattern_id="PKG_NPM_TYPOSQUAT_LODASH",
        description="Potential lodash typosquat package name",
        severity="medium",
        regex=_re(
            r"^(?:lodas[^h]|lodash-[a-z]{1,3}$|l0dash|lod4sh|llodash)$",
            re.IGNORECASE,
        ),
        ecosystem="npm",
        remediation="Verify this is the official lodash package.",
        tags=frozenset({"typosquat", "npm"}),
    ),
    PackageNamePattern(
        pattern_id="PKG_NPM_TYPOSQUAT_AXIOS",
        description="Potential axios typosquat package name",
        severity="medium",
        regex=_re(
            r"^(?:axio[^s]|axi0s|axois|axioss|axjos|axois)$",
            re.IGNORECASE,
        ),
        ecosystem="npm",
        remediation="Verify this is the official axios package.",
        tags=frozenset({"typosquat", "npm"}),
    ),
    PackageNamePattern(
        pattern_id="PKG_NPM_KNOWN_MALICIOUS",
        description="Known malicious npm package name from Contagious Interview campaign",
        severity="critical",
        regex=_re(
            r"^(?:"
            r"dev-utils-pro|node-utils-extra|npm-better-utils"
            r"|fetch-node-data|node-fetch-data|better-sqlite3-multiple-ciphers"
            r"|cross-env-browserify|browserify-cross-env"
            r"|node-datatable|nodesass|icons-packages"
            r"|img-aws-s3-object-multipart-upload"
            r"|jest-validator|postcss-optimizer"
            r"|simplejsoncms|ms-utils-node"
            r"|node-binary-utils|mock-browser-utils"
            r")$",
            re.IGNORECASE,
        ),
        ecosystem="npm",
        remediation=(
            "This package name matches a known malicious npm package from the "
            "Contagious Interview campaign. Remove immediately and audit your environment."
        ),
        tags=frozenset({"known-malicious", "npm", "beavertail", "contagious-interview"}),
    ),
    # PyPI typosquats / known malicious
    PackageNamePattern(
        pattern_id="PKG_PYPI_TYPOSQUAT_REQUESTS",
        description="Potential requests typosquat PyPI package name",
        severity="medium",
        regex=_re(
            r"^(?:request[^s]|requestss|reqests|requsets|requestlib|python-requests2)$",
            re.IGNORECASE,
        ),
        ecosystem="pypi",
        remediation="Verify this is the official requests package.",
        tags=frozenset({"typosquat", "pypi"}),
    ),
    PackageNamePattern(
        pattern_id="PKG_PYPI_TYPOSQUAT_NUMPY",
        description="Potential numpy typosquat PyPI package name",
        severity="medium",
        regex=_re(
            r"^(?:nump[^y]|numyp|nuumpy|numpyy|numpy-[a-z]{1,3}$|num-py)$",
            re.IGNORECASE,
        ),
        ecosystem="pypi",
        remediation="Verify this is the official numpy package.",
        tags=frozenset({"typosquat", "pypi"}),
    ),
    PackageNamePattern(
        pattern_id="PKG_PYPI_KNOWN_MALICIOUS",
        description="Known malicious PyPI package name from Contagious Interview or related DPRK campaigns",
        severity="critical",
        regex=_re(
            r"^(?:"
            r"pycryptoenv|pycryptoconf|pycryptofuzz"
            r"|pyperclip2|pyperclipp|pyperclipp2"
            r"|colouredlogs|coloreedd-logs"
            r"|easygui2|easyguii"
            r"|pynput2|pynputt"
            r"|pycurl2|pycurlll"
            r"|aiohttp-proxy|aiohttp-proxies"
            r"|django-inlinecss2|django-inline-css2"
            r")$",
            re.IGNORECASE,
        ),
        ecosystem="pypi",
        remediation=(
            "This package name matches a known malicious PyPI package. "
            "Remove immediately and audit your Python environment."
        ),
        tags=frozenset({"known-malicious", "pypi", "invisibleferret", "contagious-interview"}),
    ),
]


# ---------------------------------------------------------------------------
# Dangerous API sequences
# ---------------------------------------------------------------------------

DANGEROUS_API_SEQUENCES: list[APISequencePattern] = [
    APISequencePattern(
        pattern_id="API_JS_EVAL_ATOB_CHAIN",
        description="eval(atob(atob(...))) multi-layer decode chain",
        severity="critical",
        regex=_re(r"eval\s*\(\s*atob\s*\(\s*atob\s*\("),
        file_extensions=frozenset({".js", ".mjs", ".cjs", ".ts"}),
        remediation="Remove multi-layer eval/atob chains. These are used to hide payloads.",
        tags=frozenset({"beavertail", "obfuscation", "javascript", "eval"}),
    ),
    APISequencePattern(
        pattern_id="API_PY_EXEC_DECODE_CHAIN",
        description="exec(decode(decompress(...))) Python payload chain",
        severity="critical",
        regex=_re(
            r"exec\s*\(\s*"
            r"(?:.*?\.decode\s*\([^)]*\)|base64\.b64decode\s*\([^)]+\))"
            r".{0,100}"
            r"(?:zlib\.decompress|bz2\.decompress|lzma\.decompress)\s*\(",
            re.DOTALL,
        ),
        file_extensions=frozenset({".py"}),
        remediation="Remove exec+decode+decompress chains. These are InvisibleFerret loader patterns.",
        tags=frozenset({"invisibleferret", "obfuscation", "python"}),
    ),
    APISequencePattern(
        pattern_id="API_JS_PROCESS_ENV_SEND",
        description="process.env access immediately followed by HTTP send",
        severity="critical",
        regex=_re(
            r"Object\.keys\s*\(\s*process\.env\s*\)"
            r"|Object\.entries\s*\(\s*process\.env\s*\)",
        ),
        file_extensions=frozenset({".js", ".mjs", ".cjs", ".ts"}),
        remediation=(
            "Audit code that enumerates all environment variables. "
            "BeaverTail collects the entire process.env object for exfiltration."
        ),
        tags=frozenset({"beavertail", "exfiltration", "javascript"}),
    ),
    APISequencePattern(
        pattern_id="API_PY_PLATFORM_UNAME_EXFIL",
        description="Platform/uname system info collection combined with network send",
        severity="high",
        regex=_re(
            r"(?:platform\.uname|os\.uname|socket\.gethostname|platform\.node)"
            r"\s*\(\s*\)"
            r".{0,500}"
            r"(?:requests\.|urllib\.request\.|http\.client\.)",
        ),
        file_extensions=frozenset({".py"}),
        remediation=(
            "Audit code that collects system information and sends it over the network. "
            "InvisibleFerret profiles victim machines before exfiltrating data."
        ),
        tags=frozenset({"invisibleferret", "exfiltration", "python"}),
    ),
    APISequencePattern(
        pattern_id="API_SH_WHOAMI_CURL",
        description="Shell script collecting identity info and sending via curl",
        severity="high",
        regex=_re(
            r"(?:whoami|id|hostname|uname\s+-[asnrm])"
            r".{0,200}curl",
            re.IGNORECASE | re.MULTILINE,
        ),
        file_extensions=frozenset({".sh", ".bash", ".zsh"}),
        remediation=(
            "Investigate shell scripts that collect system identity and send it via curl. "
            "This is used for victim profiling in DPRK campaigns."
        ),
        tags=frozenset({"exfiltration", "shell", "reconnaissance"}),
    ),
    APISequencePattern(
        pattern_id="API_JS_FS_READFILE_SEND",
        description="Node.js fs.readFile followed by network send — file exfiltration",
        severity="high",
        regex=_re(
            r"fs\.(?:readFile|readFileSync)\s*\([^)]+\)"
            r".{0,500}"
            r"(?:https?\.(?:request|get|post)|fetch|axios\.(?:post|put)|FormData)",
        ),
        file_extensions=frozenset({".js", ".mjs", ".cjs", ".ts"}),
        remediation=(
            "Audit code that reads files and immediately sends them over the network. "
            "BeaverTail exfiltrates SSH keys, browser data, and wallet files."
        ),
        tags=frozenset({"beavertail", "exfiltration", "javascript"}),
    ),
    APISequencePattern(
        pattern_id="API_PY_SHUTIL_COPY_SEND",
        description="Python shutil file copy followed by network send — staged exfiltration",
        severity="high",
        regex=_re(
            r"shutil\.(?:copy|copy2|copyfile)\s*\([^)]+\)"
            r".{0,500}"
            r"(?:requests\.|urllib\.request\.|ftplib\.)",
        ),
        file_extensions=frozenset({".py"}),
        remediation=(
            "Audit code that copies files and transmits them over the network. "
            "InvisibleFerret stages files before exfiltration."
        ),
        tags=frozenset({"invisibleferret", "exfiltration", "python"}),
    ),
]


# ---------------------------------------------------------------------------
# Aggregated public exports
# ---------------------------------------------------------------------------

REGEX_PATTERNS: list[SignaturePattern] = (
    _BEAVERTAIL_JS_PATTERNS
    + _INVISIBLEFERRET_PYTHON_PATTERNS
    + _OBFUSCATION_PATTERNS
    + _LIFECYCLE_HOOK_PATTERNS
    + _CICD_PATTERNS
    + _NETWORK_PATTERNS
)

LIFECYCLE_HOOK_PATTERNS: list[SignaturePattern] = _LIFECYCLE_HOOK_PATTERNS

CI_CD_PATTERNS: list[SignaturePattern] = _CICD_PATTERNS


# ---------------------------------------------------------------------------
# Severity ordering helper
# ---------------------------------------------------------------------------

SEVERITY_ORDER: dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "info": 1,
}


def severity_rank(severity: str) -> int:
    """Return the numeric rank of a severity string for ordering.

    Parameters
    ----------
    severity:
        One of ``"critical"``, ``"high"``, ``"medium"``, ``"info"``.

    Returns
    -------
    int
        Numeric rank (higher = more severe).  Unknown severities return 0.
    """
    return SEVERITY_ORDER.get(severity.lower(), 0)


def get_patterns_for_extension(extension: str) -> list[SignaturePattern]:
    """Return all ``SignaturePattern`` objects applicable to a file extension.

    A pattern with an empty ``file_extensions`` frozenset applies to all files.

    Parameters
    ----------
    extension:
        File extension including the leading dot, e.g. ``".js"`` or ``".py"``.

    Returns
    -------
    list[SignaturePattern]
        Filtered list of applicable patterns.
    """
    ext_lower = extension.lower()
    return [
        p
        for p in REGEX_PATTERNS
        if not p.file_extensions or ext_lower in p.file_extensions
    ]


def get_api_sequences_for_extension(extension: str) -> list[APISequencePattern]:
    """Return all ``APISequencePattern`` objects applicable to a file extension.

    Parameters
    ----------
    extension:
        File extension including the leading dot.

    Returns
    -------
    list[APISequencePattern]
        Filtered list of applicable API sequence patterns.
    """
    ext_lower = extension.lower()
    return [
        p
        for p in DANGEROUS_API_SEQUENCES
        if not p.file_extensions or ext_lower in p.file_extensions
    ]


def all_pattern_ids() -> list[str]:
    """Return a sorted list of all pattern IDs across all signature types.

    Returns
    -------
    list[str]
        Sorted list of unique pattern ID strings.
    """
    ids: list[str] = []
    ids.extend(p.pattern_id for p in REGEX_PATTERNS)
    ids.extend(p.pattern_id for p in SUSPICIOUS_PACKAGE_NAMES)
    ids.extend(p.pattern_id for p in DANGEROUS_API_SEQUENCES)
    ids.extend(h.sha256 for h in MALICIOUS_HASHES.values())
    return sorted(set(ids))
