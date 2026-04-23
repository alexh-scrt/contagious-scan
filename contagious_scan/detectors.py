"""Core detector functions for Contagious Interview supply chain attack indicators.

Each detector function accepts file content (as a string) and a file path,
then returns a list of ``Finding`` objects describing any matches found.

Detector categories
-------------------
- ``detect_rat_patterns``       : BeaverTail / InvisibleFerret RAT signatures
- ``detect_obfuscated_loaders`` : Base64, hex, and multi-layer encoding patterns
- ``detect_eval_exec_chains``   : Dangerous eval/exec API sequences
- ``detect_lifecycle_hooks``    : npm / pip install-time hook abuse
- ``detect_cicd_patterns``      : CI/CD pipeline poisoning
- ``detect_network_iocs``       : Suspicious URLs, IPs, webhooks
- ``detect_suspicious_packages``: Typosquatting / known malicious package names
- ``detect_file_hash``          : SHA-256 hash comparison against known-malicious DB
- ``detect_all``                : Runs all detectors and aggregates results
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Sequence

from contagious_scan.signatures import (
    DANGEROUS_API_SEQUENCES,
    LIFECYCLE_HOOK_PATTERNS,
    MALICIOUS_HASHES,
    REGEX_PATTERNS,
    SUSPICIOUS_PACKAGE_NAMES,
    CI_CD_PATTERNS,
    SignaturePattern,
    APISequencePattern,
    PackageNamePattern,
    get_api_sequences_for_extension,
    get_patterns_for_extension,
    severity_rank,
)


# ---------------------------------------------------------------------------
# Finding data class
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    """A single detection finding produced by a detector function.

    Attributes
    ----------
    severity:
        One of ``"critical"``, ``"high"``, ``"medium"``, ``"info"``.
    file_path:
        Relative or absolute path of the file that triggered the finding.
    line_number:
        1-based line number of the match within the file.  ``0`` means
        the finding is file-level (e.g. a hash match).
    pattern_id:
        Unique identifier of the signature or rule that fired.
    description:
        Human-readable description of the finding.
    matched_text:
        The actual text snippet that triggered the match (may be truncated).
    remediation:
        Recommended remediation steps.
    tags:
        Frozenset of classification tags inherited from the signature.
    """

    severity: str
    file_path: str
    line_number: int
    pattern_id: str
    description: str
    matched_text: str
    remediation: str
    tags: frozenset[str] = field(default_factory=frozenset)

    def to_dict(self) -> dict[str, object]:
        """Serialise this finding to a plain dictionary.

        Returns
        -------
        dict[str, object]
            JSON-serialisable representation of the finding.
        """
        return {
            "severity": self.severity,
            "file": self.file_path,
            "line": self.line_number,
            "pattern_id": self.pattern_id,
            "description": self.description,
            "matched_text": self.matched_text,
            "remediation": self.remediation,
            "tags": sorted(self.tags),
        }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_MAX_SNIPPET_LEN = 200  # maximum characters kept from a matched snippet


def _truncate(text: str, max_len: int = _MAX_SNIPPET_LEN) -> str:
    """Truncate *text* to *max_len* characters, appending ``'...'`` if needed."""
    text = text.strip()
    if len(text) <= max_len:
        return text
    return text[:max_len] + "..."


def _line_number_of_match(content: str, match_start: int) -> int:
    """Return the 1-based line number corresponding to *match_start* in *content*."""
    return content.count("\n", 0, match_start) + 1


def _findings_from_pattern(
    pattern: SignaturePattern | APISequencePattern,
    content: str,
    file_path: str,
) -> list[Finding]:
    """Scan *content* with a single pattern and return all ``Finding`` objects.

    Parameters
    ----------
    pattern:
        A ``SignaturePattern`` or ``APISequencePattern`` from the signatures module.
    content:
        Full text content of the file being scanned.
    file_path:
        Path string used to populate ``Finding.file_path``.

    Returns
    -------
    list[Finding]
        Zero or more findings produced by this pattern.
    """
    findings: list[Finding] = []
    for match in pattern.regex.finditer(content):
        line_no = _line_number_of_match(content, match.start())
        findings.append(
            Finding(
                severity=pattern.severity,
                file_path=file_path,
                line_number=line_no,
                pattern_id=pattern.pattern_id,
                description=pattern.description,
                matched_text=_truncate(match.group(0)),
                remediation=pattern.remediation,
                tags=pattern.tags,
            )
        )
    return findings


def _get_extension(file_path: str) -> str:
    """Return the lowercase file extension (with leading dot) for *file_path*."""
    return Path(file_path).suffix.lower()


# ---------------------------------------------------------------------------
# Public detector functions
# ---------------------------------------------------------------------------


def detect_rat_patterns(
    content: str,
    file_path: str,
) -> list[Finding]:
    """Detect BeaverTail and InvisibleFerret RAT payload signatures.

    Applies all regex patterns tagged with ``"beavertail"`` or
    ``"invisibleferret"`` that are applicable to the file's extension.

    Parameters
    ----------
    content:
        Full text content of the file.
    file_path:
        Path of the file (used for extension matching and in findings).

    Returns
    -------
    list[Finding]
        All RAT-related findings for this file.
    """
    extension = _get_extension(file_path)
    rat_tags = {"beavertail", "invisibleferret"}
    applicable = [
        p
        for p in get_patterns_for_extension(extension)
        if p.tags & rat_tags
    ]
    findings: list[Finding] = []
    for pattern in applicable:
        findings.extend(_findings_from_pattern(pattern, content, file_path))
    return findings


def detect_obfuscated_loaders(
    content: str,
    file_path: str,
) -> list[Finding]:
    """Detect obfuscated loader patterns including base64, hex, and Unicode.

    Applies regex patterns tagged with ``"obfuscation"`` that are applicable
    to the file's extension.

    Parameters
    ----------
    content:
        Full text content of the file.
    file_path:
        Path of the file.

    Returns
    -------
    list[Finding]
        All obfuscation-related findings for this file.
    """
    extension = _get_extension(file_path)
    applicable = [
        p
        for p in get_patterns_for_extension(extension)
        if "obfuscation" in p.tags
    ]
    findings: list[Finding] = []
    for pattern in applicable:
        findings.extend(_findings_from_pattern(pattern, content, file_path))
    return findings


def detect_eval_exec_chains(
    content: str,
    file_path: str,
) -> list[Finding]:
    """Detect dangerous eval/exec API call chain sequences.

    Applies ``DANGEROUS_API_SEQUENCES`` entries tagged with ``"eval"`` or
    ``"exec"`` as well as all API sequences applicable to the file's extension.

    Parameters
    ----------
    content:
        Full text content of the file.
    file_path:
        Path of the file.

    Returns
    -------
    list[Finding]
        All eval/exec chain findings.
    """
    extension = _get_extension(file_path)
    applicable = get_api_sequences_for_extension(extension)
    findings: list[Finding] = []
    for pattern in applicable:
        findings.extend(_findings_from_pattern(pattern, content, file_path))

    # Also check regex patterns that are specifically eval/exec related
    exec_tags = {"eval", "exec"}
    for pattern in get_patterns_for_extension(extension):
        if pattern.tags & exec_tags:
            findings.extend(_findings_from_pattern(pattern, content, file_path))

    return findings


def detect_lifecycle_hooks(
    content: str,
    file_path: str,
) -> list[Finding]:
    """Detect malicious npm / pip lifecycle hook abuse.

    Applies ``LIFECYCLE_HOOK_PATTERNS`` entries applicable to the file's
    extension (primarily ``.json``, ``.py``, ``.toml``, ``.cfg``).

    Additionally parses ``package.json`` files with the ``json`` module to
    inspect ``scripts`` fields more precisely.

    Parameters
    ----------
    content:
        Full text content of the file.
    file_path:
        Path of the file.

    Returns
    -------
    list[Finding]
        All lifecycle hook abuse findings.
    """
    extension = _get_extension(file_path)
    filename = Path(file_path).name.lower()

    applicable = [
        p
        for p in LIFECYCLE_HOOK_PATTERNS
        if not p.file_extensions or extension in p.file_extensions
    ]

    findings: list[Finding] = []
    for pattern in applicable:
        findings.extend(_findings_from_pattern(pattern, content, file_path))

    # Additional structured analysis for package.json
    if filename == "package.json":
        findings.extend(_inspect_package_json_scripts(content, file_path))

    # Additional structured analysis for setup.py / setup.cfg
    if filename in {"setup.py", "setup.cfg"}:
        findings.extend(_inspect_setup_py(content, file_path))

    return findings


def _inspect_package_json_scripts(
    content: str,
    file_path: str,
) -> list[Finding]:
    """Parse package.json and inspect scripts fields for suspicious patterns.

    This structured check supplements the regex scan by parsing the JSON AST,
    allowing detection of patterns that span JSON values precisely.

    Parameters
    ----------
    content:
        Raw JSON content of the package.json file.
    file_path:
        Path of the file.

    Returns
    -------
    list[Finding]
        Structured findings from parsed JSON scripts inspection.
    """
    findings: list[Finding] = []
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return findings

    scripts: dict[str, str] = data.get("scripts", {})
    if not isinstance(scripts, dict):
        return findings

    # Suspicious lifecycle hook names
    dangerous_hooks = {"postinstall", "preinstall", "prepare", "prepublish", "install"}

    # Patterns to check within script values
    _dangerous_script_patterns: list[tuple[str, re.Pattern[str], str, str, str]] = [
        (
            "LH_NPM_SCRIPT_CURL",
            re.compile(r"curl\s+https?://", re.IGNORECASE),
            "critical",
            "npm lifecycle hook downloads remote content via curl",
            "Remove curl from lifecycle hooks. Scripts must not fetch remote code.",
        ),
        (
            "LH_NPM_SCRIPT_WGET",
            re.compile(r"wget\s+https?://", re.IGNORECASE),
            "critical",
            "npm lifecycle hook downloads remote content via wget",
            "Remove wget from lifecycle hooks. Scripts must not fetch remote code.",
        ),
        (
            "LH_NPM_SCRIPT_NODE_INLINE_EVAL",
            re.compile(r"node\s+-e\b", re.IGNORECASE),
            "critical",
            "npm lifecycle hook executes inline Node.js code via node -e",
            "Remove node -e from lifecycle hooks. Use explicit script files instead.",
        ),
        (
            "LH_NPM_SCRIPT_PYTHON_EXEC",
            re.compile(r"python3?\s", re.IGNORECASE),
            "high",
            "npm lifecycle hook invokes Python — potential cross-runtime dropper",
            "Audit npm lifecycle hooks that invoke Python interpreters.",
        ),
        (
            "LH_NPM_SCRIPT_PIPE_BASH",
            re.compile(r"\|\s*(?:bash|sh)\b", re.IGNORECASE),
            "critical",
            "npm lifecycle hook pipes content to bash/sh — remote code execution risk",
            "Never pipe remote content to bash/sh in npm lifecycle scripts.",
        ),
        (
            "LH_NPM_SCRIPT_B64_PAYLOAD",
            re.compile(r"[A-Za-z0-9+/]{60,}={0,2}"),
            "critical",
            "npm lifecycle hook contains base64-encoded payload",
            "Decode and review the base64 payload in this lifecycle script.",
        ),
    ]

    for hook_name, script_value in scripts.items():
        if not isinstance(script_value, str):
            continue
        is_dangerous_hook = hook_name.lower() in dangerous_hooks
        for pid, pat, severity, desc, remediation in _dangerous_script_patterns:
            # For some patterns we only fire on dangerous hooks
            if pid in {
                "LH_NPM_SCRIPT_PYTHON_EXEC",
                "LH_NPM_SCRIPT_B64_PAYLOAD",
            } and not is_dangerous_hook:
                continue
            if pat.search(script_value):
                match_obj = pat.search(script_value)
                assert match_obj is not None
                findings.append(
                    Finding(
                        severity=severity,
                        file_path=file_path,
                        line_number=0,
                        pattern_id=f"{pid}_{hook_name.upper()}",
                        description=f"{desc} (hook: {hook_name!r})",
                        matched_text=_truncate(
                            f"{hook_name}: {script_value}"
                        ),
                        remediation=remediation,
                        tags=frozenset({"lifecycle-hook", "npm"}),
                    )
                )
    return findings


def _inspect_setup_py(
    content: str,
    file_path: str,
) -> list[Finding]:
    """Inspect setup.py / setup.cfg for install-time execution indicators.

    Supplements the regex scan with heuristic checks for command string
    patterns that are not caught by the generic patterns.

    Parameters
    ----------
    content:
        Raw content of the setup file.
    file_path:
        Path of the file.

    Returns
    -------
    list[Finding]
        Structured findings from setup file inspection.
    """
    findings: list[Finding] = []

    # Patterns: (pattern_id, regex, severity, description, remediation)
    _setup_patterns: list[tuple[str, re.Pattern[str], str, str, str]] = [
        (
            "LH_SETUP_CMDCLASS_RUN",
            re.compile(
                r"class\s+\w+\s*\(\s*(?:install|build|develop|egg_info)\s*\)",
                re.IGNORECASE,
            ),
            "medium",
            "Custom setup command class overriding install/build — inspect for malicious run() method",
            "Review custom setup command classes for malicious code in run() methods.",
        ),
        (
            "LH_SETUP_ATEXIT_EXEC",
            re.compile(r"atexit\.register", re.IGNORECASE),
            "high",
            "atexit.register() in setup file — code executed at interpreter exit",
            "Remove atexit.register() from setup files. This is used to run code during installation.",
        ),
        (
            "LH_SETUP_TEMPFILE_EXEC",
            re.compile(
                r"(?:tempfile\.(?:mkstemp|NamedTemporaryFile|mkdtemp))",
                re.IGNORECASE,
            ),
            "medium",
            "Temporary file creation in setup.py — may stage and execute payload",
            "Audit temporary file usage in setup.py for staged execution patterns.",
        ),
    ]

    for pid, pat, severity, desc, remediation in _setup_patterns:
        for match in pat.finditer(content):
            line_no = _line_number_of_match(content, match.start())
            findings.append(
                Finding(
                    severity=severity,
                    file_path=file_path,
                    line_number=line_no,
                    pattern_id=pid,
                    description=desc,
                    matched_text=_truncate(match.group(0)),
                    remediation=remediation,
                    tags=frozenset({"lifecycle-hook", "pypi", "python"}),
                )
            )
    return findings


def detect_cicd_patterns(
    content: str,
    file_path: str,
) -> list[Finding]:
    """Detect CI/CD pipeline poisoning patterns.

    Applies ``CI_CD_PATTERNS`` entries applicable to the file's extension
    (primarily ``.yml`` / ``.yaml``).

    Parameters
    ----------
    content:
        Full text content of the file.
    file_path:
        Path of the file.

    Returns
    -------
    list[Finding]
        All CI/CD poisoning findings.
    """
    extension = _get_extension(file_path)
    applicable = [
        p
        for p in CI_CD_PATTERNS
        if not p.file_extensions or extension in p.file_extensions
    ]
    findings: list[Finding] = []
    for pattern in applicable:
        findings.extend(_findings_from_pattern(pattern, content, file_path))
    return findings


def detect_network_iocs(
    content: str,
    file_path: str,
) -> list[Finding]:
    """Detect suspicious network IOCs: C2 URLs, raw IPs, webhook exfiltration.

    Applies regex patterns tagged with ``"network"`` or ``"c2"`` or
    ``"exfiltration"`` that are applicable to the file's extension.

    Parameters
    ----------
    content:
        Full text content of the file.
    file_path:
        Path of the file.

    Returns
    -------
    list[Finding]
        All network IOC findings.
    """
    extension = _get_extension(file_path)
    network_tags = {"network", "c2", "exfiltration"}
    applicable = [
        p
        for p in get_patterns_for_extension(extension)
        if p.tags & network_tags
    ]
    findings: list[Finding] = []
    for pattern in applicable:
        findings.extend(_findings_from_pattern(pattern, content, file_path))
    return findings


def detect_suspicious_packages(
    content: str,
    file_path: str,
) -> list[Finding]:
    """Detect suspicious / typosquatting package names in manifest files.

    Parses ``package.json`` and ``requirements.txt`` / ``Pipfile`` /
    ``pyproject.toml`` to extract dependency names and match them against
    ``SUSPICIOUS_PACKAGE_NAMES``.

    Also applies package name patterns directly against the raw file content
    for cases where structured parsing is insufficient.

    Parameters
    ----------
    content:
        Full text content of the file.
    file_path:
        Path of the file.

    Returns
    -------
    list[Finding]
        All suspicious package name findings.
    """
    findings: list[Finding] = []
    filename = Path(file_path).name.lower()

    if filename == "package.json":
        findings.extend(_check_npm_dependencies(content, file_path))
    elif filename in {"requirements.txt", "pipfile", "pyproject.toml", "setup.cfg", "setup.py"}:
        findings.extend(_check_pypi_dependencies(content, file_path))
    else:
        # Fallback: raw content scan for all package patterns
        for pkg_pattern in SUSPICIOUS_PACKAGE_NAMES:
            for line_no, line in enumerate(content.splitlines(), start=1):
                for token in re.split(r'[\s,"\'=><;(){}\[\]]+', line):
                    token = token.strip()
                    if token and pkg_pattern.regex.match(token):
                        findings.append(
                            Finding(
                                severity=pkg_pattern.severity,
                                file_path=file_path,
                                line_number=line_no,
                                pattern_id=pkg_pattern.pattern_id,
                                description=pkg_pattern.description,
                                matched_text=_truncate(token),
                                remediation=pkg_pattern.remediation,
                                tags=pkg_pattern.tags,
                            )
                        )
    return findings


def _check_npm_dependencies(
    content: str,
    file_path: str,
) -> list[Finding]:
    """Extract dependency names from package.json and check for suspicious names.

    Parameters
    ----------
    content:
        Raw JSON content of package.json.
    file_path:
        Path of the file.

    Returns
    -------
    list[Finding]
        Findings for any suspicious npm dependency names detected.
    """
    findings: list[Finding] = []
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return findings

    dep_fields = [
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
        "bundledDependencies",
        "bundleDependencies",
    ]
    npm_patterns = [
        p for p in SUSPICIOUS_PACKAGE_NAMES
        if p.ecosystem in {"npm", "any"}
    ]

    for field_name in dep_fields:
        deps = data.get(field_name, {})
        if not isinstance(deps, dict):
            continue
        for pkg_name in deps:
            if not isinstance(pkg_name, str):
                continue
            for pkg_pattern in npm_patterns:
                if pkg_pattern.regex.match(pkg_name):
                    findings.append(
                        Finding(
                            severity=pkg_pattern.severity,
                            file_path=file_path,
                            line_number=0,
                            pattern_id=pkg_pattern.pattern_id,
                            description=(
                                f"{pkg_pattern.description} — package: {pkg_name!r} "
                                f"in {field_name!r}"
                            ),
                            matched_text=pkg_name,
                            remediation=pkg_pattern.remediation,
                            tags=pkg_pattern.tags,
                        )
                    )
    return findings


def _check_pypi_dependencies(
    content: str,
    file_path: str,
) -> list[Finding]:
    """Extract PyPI dependency names from Python manifest files.

    Handles ``requirements.txt``, ``Pipfile``, ``pyproject.toml``, and
    ``setup.cfg`` by applying simple line-oriented tokenisation.

    Parameters
    ----------
    content:
        Raw content of the Python package manifest.
    file_path:
        Path of the file.

    Returns
    -------
    list[Finding]
        Findings for any suspicious PyPI dependency names detected.
    """
    findings: list[Finding] = []
    pypi_patterns = [
        p for p in SUSPICIOUS_PACKAGE_NAMES
        if p.ecosystem in {"pypi", "any"}
    ]

    for line_no, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        # Skip comments and empty lines
        if not stripped or stripped.startswith("#") or stripped.startswith("["):
            continue
        # Extract the package name (before any version specifier)
        pkg_name = re.split(r"[>=<!;\[\s]", stripped)[0].strip()
        # Strip quotes (for toml/pipfile formats)
        pkg_name = pkg_name.strip('"\'\'"')
        if not pkg_name:
            continue
        for pkg_pattern in pypi_patterns:
            if pkg_pattern.regex.match(pkg_name):
                findings.append(
                    Finding(
                        severity=pkg_pattern.severity,
                        file_path=file_path,
                        line_number=line_no,
                        pattern_id=pkg_pattern.pattern_id,
                        description=(
                            f"{pkg_pattern.description} — package: {pkg_name!r}"
                        ),
                        matched_text=pkg_name,
                        remediation=pkg_pattern.remediation,
                        tags=pkg_pattern.tags,
                    )
                )
    return findings


def detect_file_hash(
    content: str,
    file_path: str,
) -> list[Finding]:
    """Compare the SHA-256 hash of *content* against the known-malicious hash database.

    Parameters
    ----------
    content:
        Full text content of the file (decoded as UTF-8 or best-effort).
    file_path:
        Path of the file.

    Returns
    -------
    list[Finding]
        A single finding if the file hash is in ``MALICIOUS_HASHES``, else empty.
    """
    sha256 = hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()
    if sha256 in MALICIOUS_HASHES:
        record = MALICIOUS_HASHES[sha256]
        return [
            Finding(
                severity=record.severity,
                file_path=file_path,
                line_number=0,
                pattern_id="HASH_MATCH_" + sha256[:8].upper(),
                description=(
                    f"File hash matches known malicious sample: {record.description}"
                ),
                matched_text=sha256,
                remediation=(
                    "This file matches a known malicious payload. "
                    "Remove it immediately and investigate your environment."
                ),
                tags=record.tags,
            )
        ]
    return []


def detect_file_hash_bytes(
    data: bytes,
    file_path: str,
) -> list[Finding]:
    """Compare the SHA-256 hash of raw *data* bytes against the known-malicious database.

    This variant accepts raw bytes, which is more accurate than the string-based
    ``detect_file_hash`` when files may contain binary content.

    Parameters
    ----------
    data:
        Raw file bytes.
    file_path:
        Path of the file.

    Returns
    -------
    list[Finding]
        A single finding if the file hash is in ``MALICIOUS_HASHES``, else empty.
    """
    sha256 = hashlib.sha256(data).hexdigest()
    if sha256 in MALICIOUS_HASHES:
        record = MALICIOUS_HASHES[sha256]
        return [
            Finding(
                severity=record.severity,
                file_path=file_path,
                line_number=0,
                pattern_id="HASH_MATCH_" + sha256[:8].upper(),
                description=(
                    f"File hash matches known malicious sample: {record.description}"
                ),
                matched_text=sha256,
                remediation=(
                    "This file matches a known malicious payload. "
                    "Remove it immediately and investigate your environment."
                ),
                tags=record.tags,
            )
        ]
    return []


def _deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    """Remove duplicate findings based on (file_path, line_number, pattern_id).

    Parameters
    ----------
    findings:
        List of findings that may contain duplicates.

    Returns
    -------
    list[Finding]
        Deduplicated list preserving original ordering.
    """
    seen: set[tuple[str, int, str]] = set()
    unique: list[Finding] = []
    for f in findings:
        key = (f.file_path, f.line_number, f.pattern_id)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def detect_all(
    content: str,
    file_path: str,
) -> list[Finding]:
    """Run all detectors against *content* and return aggregated findings.

    Executes each specialised detector in sequence, deduplicates the combined
    results, and returns them sorted by descending severity then file path.

    Parameters
    ----------
    content:
        Full text content of the file.
    file_path:
        Path of the file.

    Returns
    -------
    list[Finding]
        Deduplicated, severity-sorted list of all findings for this file.
    """
    all_findings: list[Finding] = []

    detectors: list[Callable[[str, str], list[Finding]]] = [
        detect_rat_patterns,
        detect_obfuscated_loaders,
        detect_eval_exec_chains,
        detect_lifecycle_hooks,
        detect_cicd_patterns,
        detect_network_iocs,
        detect_suspicious_packages,
        detect_file_hash,
    ]

    for detector in detectors:
        try:
            all_findings.extend(detector(content, file_path))
        except Exception:  # noqa: BLE001
            # Individual detector failures must not abort the whole scan
            pass

    unique = _deduplicate_findings(all_findings)
    unique.sort(key=lambda f: severity_rank(f.severity), reverse=True)
    return unique


def filter_findings_by_severity(
    findings: list[Finding],
    min_severity: str,
) -> list[Finding]:
    """Return only findings at or above the specified minimum severity.

    Parameters
    ----------
    findings:
        List of ``Finding`` objects to filter.
    min_severity:
        Minimum severity string: ``"critical"``, ``"high"``, ``"medium"``,
        or ``"info"``.

    Returns
    -------
    list[Finding]
        Filtered list containing only findings whose severity rank is
        greater than or equal to the rank of *min_severity*.
    """
    min_rank = severity_rank(min_severity.lower())
    return [f for f in findings if severity_rank(f.severity) >= min_rank]


def findings_have_severity(
    findings: list[Finding],
    min_severity: str,
) -> bool:
    """Return ``True`` if any finding in *findings* meets *min_severity*.

    Parameters
    ----------
    findings:
        List of ``Finding`` objects to inspect.
    min_severity:
        Minimum severity threshold.

    Returns
    -------
    bool
        ``True`` if at least one finding is at or above *min_severity*.
    """
    return bool(filter_findings_by_severity(findings, min_severity))
