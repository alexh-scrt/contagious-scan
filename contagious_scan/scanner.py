"""Scanner orchestration for contagious_scan.

The :class:`Scanner` class orchestrates the full scan pipeline:

1. File discovery (working tree, staged files, or remote clone)
2. Detector dispatch for each discovered file
3. Findings aggregation and deduplication
4. Summary statistics generation

Typical usage::

    from contagious_scan.scanner import Scanner, ScanConfig, ScanResult

    config = ScanConfig(target_path="/path/to/repo", staged_only=False)
    scanner = Scanner(config)
    result = scanner.run()
    print(f"Found {result.total_findings} findings")
"""

from __future__ import annotations

import datetime
import logging
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterator

from contagious_scan.detectors import (
    Finding,
    detect_all,
    detect_cicd_patterns,
    detect_eval_exec_chains,
    detect_file_hash,
    detect_file_hash_bytes,
    detect_lifecycle_hooks,
    detect_network_iocs,
    detect_obfuscated_loaders,
    detect_rat_patterns,
    detect_suspicious_packages,
    filter_findings_by_severity,
    findings_have_severity,
)
from contagious_scan.git_utils import (
    CloneError,
    NotAGitRepoError,
    clone_remote_repo,
    get_commit_history_files,
    get_files_from_directory,
    get_repo_files,
    get_staged_files,
    is_git_repo,
    read_file_content,
)
from contagious_scan.signatures import severity_rank

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Configuration data classes
# ---------------------------------------------------------------------------


@dataclass
class ScanConfig:
    """Configuration for a single scan run.

    Attributes
    ----------
    target_path:
        Local path to the repository or directory to scan.  When
        ``remote_url`` is provided, this becomes the clone destination
        (or a temp dir is used if left empty).
    remote_url:
        Optional remote Git URL.  When set, the repository is cloned
        before scanning.
    staged_only:
        If ``True``, only scan files currently staged in the Git index.
        Useful in pre-push hook mode.
    include_history:
        If ``True``, also scan file contents from commit history
        (up to ``history_depth`` commits).
    history_depth:
        Number of commits to inspect when ``include_history`` is ``True``.
        Defaults to 20.
    min_severity:
        Minimum severity level to include in results.  One of
        ``"critical"``, ``"high"``, ``"medium"``, ``"info"``.
        Defaults to ``"info"`` (all findings).
    include_untracked:
        If ``True``, also scan untracked (new) files in the working tree.
        Only relevant when ``staged_only=False``.
    clone_depth:
        Shallow clone depth for remote scans.  ``None`` for full clone.
    branch:
        Branch to scan / clone.  ``None`` uses the default branch.
    skip_extensions:
        Set of file extensions to skip during scanning.
    extra_detectors:
        Optional list of additional detector callables to run in addition
        to the built-in ones.  Each callable must have the signature
        ``(content: str, file_path: str) -> list[Finding]``.
    """

    target_path: str | Path = Path(".")
    remote_url: str | None = None
    staged_only: bool = False
    include_history: bool = False
    history_depth: int = 20
    min_severity: str = "info"
    include_untracked: bool = False
    clone_depth: int | None = 1
    branch: str | None = None
    skip_extensions: frozenset[str] = field(default_factory=frozenset)
    extra_detectors: list[Callable[[str, str], list[Finding]]] = field(
        default_factory=list
    )

    def __post_init__(self) -> None:
        """Normalise and validate configuration values."""
        self.target_path = Path(self.target_path)
        self.min_severity = self.min_severity.lower()
        if self.min_severity not in {"critical", "high", "medium", "info"}:
            raise ValueError(
                f"Invalid min_severity '{self.min_severity}'. "
                "Must be one of: critical, high, medium, info"
            )


# ---------------------------------------------------------------------------
# Result data classes
# ---------------------------------------------------------------------------


@dataclass
class ScanResult:
    """Aggregated results from a completed scan.

    Attributes
    ----------
    repository:
        Path or URL of the scanned target.
    scan_timestamp:
        ISO-8601 UTC timestamp of when the scan completed.
    findings:
        All findings meeting the configured minimum severity.
    scanned_files:
        List of relative paths of all files that were scanned.
    skipped_files:
        List of files that were skipped (too large, binary, read error).
    errors:
        List of error messages encountered during scanning.
    config:
        The :class:`ScanConfig` that produced this result.
    elapsed_seconds:
        Wall-clock time the scan took in seconds.
    """

    repository: str
    scan_timestamp: str
    findings: list[Finding]
    scanned_files: list[str]
    skipped_files: list[str]
    errors: list[str]
    config: ScanConfig
    elapsed_seconds: float = 0.0

    @property
    def total_findings(self) -> int:
        """Total number of findings in this result."""
        return len(self.findings)

    @property
    def findings_by_severity(self) -> dict[str, list[Finding]]:
        """Return findings grouped by severity.

        Returns
        -------
        dict[str, list[Finding]]
            Keys are severity strings; values are lists of findings.
        """
        grouped: dict[str, list[Finding]] = {
            "critical": [],
            "high": [],
            "medium": [],
            "info": [],
        }
        for f in self.findings:
            grouped.setdefault(f.severity, []).append(f)
        return grouped

    @property
    def has_critical(self) -> bool:
        """Return ``True`` if any critical-severity finding is present."""
        return findings_have_severity(self.findings, "critical")

    @property
    def has_high_or_above(self) -> bool:
        """Return ``True`` if any high-or-above finding is present."""
        return findings_have_severity(self.findings, "high")

    def to_dict(self) -> dict[str, object]:
        """Serialise the scan result to a plain dictionary.

        Returns
        -------
        dict[str, object]
            JSON-serialisable representation of the scan result.
        """
        by_sev = self.findings_by_severity
        return {
            "scan_timestamp": self.scan_timestamp,
            "repository": self.repository,
            "total_findings": self.total_findings,
            "severity_summary": {
                sev: len(findings) for sev, findings in by_sev.items()
            },
            "findings": [f.to_dict() for f in self.findings],
            "scanned_files_count": len(self.scanned_files),
            "skipped_files_count": len(self.skipped_files),
            "errors": self.errors,
            "elapsed_seconds": self.elapsed_seconds,
        }


# ---------------------------------------------------------------------------
# Progress callback type
# ---------------------------------------------------------------------------

ProgressCallback = Callable[[str, int, int], None]
"""
Optional callback called after each file is scanned.

Signature: ``callback(file_path: str, files_done: int, total_files: int)``
"""


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------


class Scanner:
    """Orchestrates the full scan pipeline.

    Parameters
    ----------
    config:
        A :class:`ScanConfig` instance controlling scan behaviour.
    progress_callback:
        Optional callable invoked after each file is processed.
        Signature: ``(file_path, files_done, total_files)``.

    Examples
    --------
    Basic usage::

        config = ScanConfig(target_path="/path/to/repo")
        scanner = Scanner(config)
        result = scanner.run()

    Staged-only (hook mode)::

        config = ScanConfig(target_path=".", staged_only=True)
        result = Scanner(config).run()
    """

    def __init__(
        self,
        config: ScanConfig,
        progress_callback: ProgressCallback | None = None,
    ) -> None:
        self._config = config
        self._progress_callback = progress_callback
        self._temp_clone_dir: Path | None = None

    def run(self) -> ScanResult:
        """Execute the full scan pipeline and return a :class:`ScanResult`.

        Returns
        -------
        ScanResult
            Aggregated scan results.

        Raises
        ------
        CloneError
            If remote cloning fails.
        ValueError
            If the target path does not exist.
        """
        import time

        start_time = time.monotonic()
        scan_time = datetime.datetime.utcnow().isoformat() + "Z"

        all_findings: list[Finding] = []
        scanned_files: list[str] = []
        skipped_files: list[str] = []
        errors: list[str] = []

        # ----------------------------------------------------------------
        # Step 1: Resolve target (clone remote if needed)
        # ----------------------------------------------------------------
        target_path, repository_label = self._resolve_target(errors)
        if target_path is None:
            return ScanResult(
                repository=repository_label,
                scan_timestamp=scan_time,
                findings=[],
                scanned_files=[],
                skipped_files=[],
                errors=errors,
                config=self._config,
                elapsed_seconds=time.monotonic() - start_time,
            )

        # ----------------------------------------------------------------
        # Step 2: Discover files to scan
        # ----------------------------------------------------------------
        files_to_scan = self._discover_files(target_path, errors)
        total_files = len(files_to_scan)
        logger.info(
            "Discovered %d files to scan in '%s'", total_files, target_path
        )

        # ----------------------------------------------------------------
        # Step 3: Scan each file
        # ----------------------------------------------------------------
        for idx, file_path in enumerate(files_to_scan, start=1):
            rel_path = self._relative_path(file_path, target_path)

            if self._should_skip_extension(file_path):
                skipped_files.append(str(rel_path))
                continue

            try:
                text, raw = read_file_content(file_path)
            except ValueError as exc:
                # File too large
                logger.debug("Skipping '%s': %s", rel_path, exc)
                skipped_files.append(str(rel_path))
                continue
            except OSError as exc:
                msg = f"Cannot read '{rel_path}': {exc}"
                logger.warning(msg)
                errors.append(msg)
                skipped_files.append(str(rel_path))
                continue

            file_findings = self._scan_file(text, raw, str(rel_path))
            all_findings.extend(file_findings)
            scanned_files.append(str(rel_path))

            if self._progress_callback is not None:
                try:
                    self._progress_callback(str(rel_path), idx, total_files)
                except Exception:  # noqa: BLE001
                    pass

        # ----------------------------------------------------------------
        # Step 4: Scan commit history (if requested)
        # ----------------------------------------------------------------
        if self._config.include_history and is_git_repo(target_path):
            history_findings = self._scan_history(
                target_path, errors, scanned_files
            )
            all_findings.extend(history_findings)

        # ----------------------------------------------------------------
        # Step 5: Filter, deduplicate, and sort findings
        # ----------------------------------------------------------------
        filtered = filter_findings_by_severity(
            all_findings, self._config.min_severity
        )
        deduped = self._deduplicate(filtered)
        deduped.sort(
            key=lambda f: (
                -severity_rank(f.severity),
                f.file_path,
                f.line_number,
            )
        )

        # ----------------------------------------------------------------
        # Step 6: Cleanup temp clone
        # ----------------------------------------------------------------
        self._cleanup_temp_clone()

        elapsed = time.monotonic() - start_time

        return ScanResult(
            repository=repository_label,
            scan_timestamp=scan_time,
            findings=deduped,
            scanned_files=scanned_files,
            skipped_files=skipped_files,
            errors=errors,
            config=self._config,
            elapsed_seconds=elapsed,
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _resolve_target(
        self, errors: list[str]
    ) -> tuple[Path | None, str]:
        """Resolve the scan target, cloning remote repos if necessary.

        Parameters
        ----------
        errors:
            Mutable list to append error messages to.

        Returns
        -------
        tuple[Path | None, str]
            ``(local_path, repository_label)`` where *local_path* is
            ``None`` if resolution failed.
        """
        if self._config.remote_url:
            repository_label = self._config.remote_url
            try:
                target_path = clone_remote_repo(
                    self._config.remote_url,
                    target_dir=(
                        self._config.target_path
                        if self._config.target_path != Path(".")
                        else None
                    ),
                    depth=self._config.clone_depth,
                    branch=self._config.branch,
                )
                self._temp_clone_dir = target_path
                logger.info("Cloned '%s' to '%s'", repository_label, target_path)
            except CloneError as exc:
                errors.append(str(exc))
                return None, repository_label
        else:
            target_path = Path(self._config.target_path).resolve()
            repository_label = str(target_path)
            if not target_path.exists():
                errors.append(f"Target path does not exist: '{target_path}'")
                return None, repository_label

        return target_path, repository_label

    def _discover_files(self, target_path: Path, errors: list[str]) -> list[Path]:
        """Discover files to scan based on configuration.

        Parameters
        ----------
        target_path:
            Resolved local path of the scan target.
        errors:
            Mutable list to append error messages to.

        Returns
        -------
        list[Path]
            Ordered list of absolute file paths to scan.
        """
        if self._config.staged_only:
            return self._discover_staged(target_path, errors)

        if is_git_repo(target_path):
            return self._discover_git_files(target_path, errors)

        # Not a git repo — fall back to directory walk
        logger.debug(
            "'%s' is not a Git repository; scanning as directory.", target_path
        )
        try:
            return get_files_from_directory(target_path)
        except ValueError as exc:
            errors.append(str(exc))
            return []

    def _discover_staged(self, target_path: Path, errors: list[str]) -> list[Path]:
        """Return staged files for hook-mode scanning.

        Parameters
        ----------
        target_path:
            Repository path.
        errors:
            Mutable list to append error messages to.

        Returns
        -------
        list[Path]
            Staged file paths.
        """
        if not is_git_repo(target_path):
            errors.append(
                f"--staged-only requires a Git repository, but '{target_path}' "
                "is not one."
            )
            return []
        try:
            return get_staged_files(target_path)
        except NotAGitRepoError as exc:
            errors.append(str(exc))
            return []
        except Exception as exc:  # noqa: BLE001
            msg = f"Error enumerating staged files: {exc}"
            logger.warning(msg)
            errors.append(msg)
            return []

    def _discover_git_files(
        self, target_path: Path, errors: list[str]
    ) -> list[Path]:
        """Return all tracked (and optionally untracked) Git files.

        Parameters
        ----------
        target_path:
            Repository path.
        errors:
            Mutable list to append error messages to.

        Returns
        -------
        list[Path]
            File paths to scan.
        """
        try:
            return get_repo_files(
                target_path,
                include_untracked=self._config.include_untracked,
            )
        except NotAGitRepoError as exc:
            errors.append(str(exc))
            return []
        except Exception as exc:  # noqa: BLE001
            msg = f"Error enumerating repository files: {exc}"
            logger.warning(msg)
            errors.append(msg)
            # Fall back to directory walk
            try:
                return get_files_from_directory(target_path)
            except ValueError:
                return []

    def _scan_file(
        self,
        text: str,
        raw: bytes,
        rel_path: str,
    ) -> list[Finding]:
        """Run all detectors against a single file.

        Parameters
        ----------
        text:
            Decoded text content of the file.
        raw:
            Raw bytes of the file (used for hash check).
        rel_path:
            Relative path string used in findings.

        Returns
        -------
        list[Finding]
            All findings for this file from all detectors.
        """
        findings: list[Finding] = []

        # Built-in regex/structural detectors
        try:
            findings.extend(detect_all(text, rel_path))
        except Exception as exc:  # noqa: BLE001
            logger.debug("detect_all failed for '%s': %s", rel_path, exc)

        # Raw-bytes hash check (more accurate than string-based)
        try:
            findings.extend(detect_file_hash_bytes(raw, rel_path))
        except Exception as exc:  # noqa: BLE001
            logger.debug("detect_file_hash_bytes failed for '%s': %s", rel_path, exc)

        # Extra user-supplied detectors
        for extra_detector in self._config.extra_detectors:
            try:
                findings.extend(extra_detector(text, rel_path))
            except Exception as exc:  # noqa: BLE001
                logger.debug(
                    "Extra detector %s failed for '%s': %s",
                    getattr(extra_detector, "__name__", repr(extra_detector)),
                    rel_path,
                    exc,
                )

        return findings

    def _scan_history(
        self,
        target_path: Path,
        errors: list[str],
        scanned_files: list[str],
    ) -> list[Finding]:
        """Scan files from commit history.

        Parameters
        ----------
        target_path:
            Repository path.
        errors:
            Mutable list to append error messages to.
        scanned_files:
            Mutable list to append scanned file references to.

        Returns
        -------
        list[Finding]
            Findings from historical file contents.
        """
        findings: list[Finding] = []
        logger.info(
            "Scanning commit history (depth=%d)", self._config.history_depth
        )
        try:
            history_items = get_commit_history_files(
                target_path,
                max_commits=self._config.history_depth,
                branch=self._config.branch,
            )
        except Exception as exc:  # noqa: BLE001
            msg = f"Error scanning commit history: {exc}"
            logger.warning(msg)
            errors.append(msg)
            return findings

        for commit_sha, rel_path, content_bytes in history_items:
            if self._should_skip_extension(Path(rel_path)):
                continue
            hist_ref = f"{rel_path}@{commit_sha[:8]}"
            try:
                text = content_bytes.decode("utf-8", errors="replace")
            except Exception:  # noqa: BLE001
                continue

            file_findings = self._scan_file(text, content_bytes, hist_ref)
            findings.extend(file_findings)
            if hist_ref not in scanned_files:
                scanned_files.append(hist_ref)

        return findings

    def _should_skip_extension(self, file_path: Path) -> bool:
        """Return ``True`` if this file's extension is in the skip set.

        Parameters
        ----------
        file_path:
            File path to check.

        Returns
        -------
        bool
            ``True`` if the file should be skipped.
        """
        if not self._config.skip_extensions:
            return False
        ext = file_path.suffix.lower()
        return ext in self._config.skip_extensions

    @staticmethod
    def _relative_path(abs_path: Path, base: Path) -> Path:
        """Return *abs_path* relative to *base*, or *abs_path* if not relative.

        Parameters
        ----------
        abs_path:
            Absolute file path.
        base:
            Base directory.

        Returns
        -------
        Path
            Relative path when possible, otherwise the absolute path.
        """
        try:
            return abs_path.relative_to(base)
        except ValueError:
            return abs_path

    @staticmethod
    def _deduplicate(findings: list[Finding]) -> list[Finding]:
        """Remove duplicate findings.

        Parameters
        ----------
        findings:
            Potentially duplicate list of findings.

        Returns
        -------
        list[Finding]
            Deduplicated list preserving first occurrence order.
        """
        seen: set[tuple[str, int, str]] = set()
        unique: list[Finding] = []
        for f in findings:
            key = (f.file_path, f.line_number, f.pattern_id)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

    def _cleanup_temp_clone(self) -> None:
        """Remove the temporary clone directory if one was created."""
        if self._temp_clone_dir is not None:
            try:
                shutil.rmtree(str(self._temp_clone_dir), ignore_errors=True)
                logger.debug(
                    "Removed temporary clone directory '%s'",
                    self._temp_clone_dir,
                )
            except Exception as exc:  # noqa: BLE001
                logger.debug(
                    "Could not remove temp clone dir '%s': %s",
                    self._temp_clone_dir, exc
                )
            finally:
                self._temp_clone_dir = None


# ---------------------------------------------------------------------------
# Convenience function
# ---------------------------------------------------------------------------


def scan(
    target: str | Path,
    staged_only: bool = False,
    min_severity: str = "info",
    include_history: bool = False,
    history_depth: int = 20,
    include_untracked: bool = False,
    remote_url: str | None = None,
    branch: str | None = None,
    clone_depth: int | None = 1,
    progress_callback: ProgressCallback | None = None,
    extra_detectors: list[Callable[[str, str], list[Finding]]] | None = None,
) -> ScanResult:
    """Convenience wrapper to run a scan with minimal configuration.

    Parameters
    ----------
    target:
        Local path to scan (or clone destination when *remote_url* is given).
    staged_only:
        If ``True``, only scan staged files.
    min_severity:
        Minimum severity to include in results.
    include_history:
        If ``True``, scan commit history as well.
    history_depth:
        Number of commits to inspect when *include_history* is ``True``.
    include_untracked:
        If ``True``, also scan untracked files.
    remote_url:
        Remote repository URL to clone and scan.
    branch:
        Branch to scan / clone.
    clone_depth:
        Shallow clone depth for remote scans.
    progress_callback:
        Optional progress callback ``(file_path, done, total)``.
    extra_detectors:
        Optional list of additional detector callables.

    Returns
    -------
    ScanResult
        The completed scan result.
    """
    config = ScanConfig(
        target_path=target,
        remote_url=remote_url,
        staged_only=staged_only,
        include_history=include_history,
        history_depth=history_depth,
        min_severity=min_severity,
        include_untracked=include_untracked,
        clone_depth=clone_depth,
        branch=branch,
        extra_detectors=extra_detectors or [],
    )
    return Scanner(config, progress_callback=progress_callback).run()
