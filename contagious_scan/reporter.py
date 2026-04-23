"""Reporter module for contagious_scan.

Renders scan results in three formats:

- **rich**: Colour-coded terminal tables using the ``rich`` library.
- **json**: Machine-readable JSON output suitable for CI pipelines.
- **plain**: Plain-text output with no ANSI codes for logging / redirection.

Exit code semantics
-------------------
- ``0`` : No findings at or above the minimum severity threshold.
- ``1`` : One or more findings at or above the minimum severity threshold.
- ``2`` : Scan error (invalid path, git error, etc.).

Typical usage::

    from contagious_scan.reporter import Reporter, OutputFormat
    from contagious_scan.scanner import ScanResult

    reporter = Reporter(output_format=OutputFormat.RICH, min_severity="high")
    exit_code = reporter.render(result)
    raise SystemExit(exit_code)
"""

from __future__ import annotations

import json
import sys
from enum import Enum
from io import StringIO
from typing import TextIO

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from contagious_scan.detectors import Finding, filter_findings_by_severity
from contagious_scan.signatures import severity_rank

# Lazy import to avoid circular deps — scanner is imported only for type hints.
if False:  # TYPE_CHECKING
    from contagious_scan.scanner import ScanResult  # noqa: F401


# ---------------------------------------------------------------------------
# Exit codes
# ---------------------------------------------------------------------------

EXIT_OK: int = 0
"""No findings at or above the minimum severity."""

EXIT_FINDINGS: int = 1
"""One or more findings at or above the minimum severity."""

EXIT_ERROR: int = 2
"""Scan error encountered."""


# ---------------------------------------------------------------------------
# Severity colour mapping
# ---------------------------------------------------------------------------

_SEVERITY_STYLE: dict[str, str] = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "info": "cyan",
}

_SEVERITY_EMOJI: dict[str, str] = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "info": "🔵",
}


# ---------------------------------------------------------------------------
# Output format enum
# ---------------------------------------------------------------------------


class OutputFormat(str, Enum):
    """Supported output formats for the reporter.

    Attributes
    ----------
    RICH:
        Colour-coded terminal table using the ``rich`` library.
    JSON:
        Machine-readable JSON output.
    PLAIN:
        Plain-text output with no ANSI codes.
    """

    RICH = "rich"
    JSON = "json"
    PLAIN = "plain"

    @classmethod
    def from_string(cls, value: str) -> "OutputFormat":
        """Parse a format string into an ``OutputFormat`` enum value.

        Parameters
        ----------
        value:
            Case-insensitive format name (``"rich"``, ``"json"``, ``"plain"``).

        Returns
        -------
        OutputFormat
            Matching enum value.

        Raises
        ------
        ValueError
            If *value* does not match a known format.
        """
        try:
            return cls(value.lower())
        except ValueError:
            valid = ", ".join(f.value for f in cls)
            raise ValueError(
                f"Unknown output format '{value}'. Valid formats: {valid}"
            )


# ---------------------------------------------------------------------------
# Reporter
# ---------------------------------------------------------------------------


class Reporter:
    """Renders :class:`~contagious_scan.scanner.ScanResult` objects.

    Parameters
    ----------
    output_format:
        One of ``OutputFormat.RICH``, ``OutputFormat.JSON``, or
        ``OutputFormat.PLAIN``.
    min_severity:
        Minimum severity level to include in output and exit-code logic.
        One of ``"critical"``, ``"high"``, ``"medium"``, ``"info"``.
    file:
        Output stream.  Defaults to ``sys.stdout``.
    ci_override:
        If ``True``, always return exit code ``0`` even when findings are
        present.  Useful for CI pipelines that should not be blocked.

    Examples
    --------
    ::

        reporter = Reporter(OutputFormat.RICH, min_severity="high")
        exit_code = reporter.render(scan_result)
    """

    def __init__(
        self,
        output_format: OutputFormat = OutputFormat.RICH,
        min_severity: str = "info",
        file: TextIO | None = None,
        ci_override: bool = False,
    ) -> None:
        self._format = output_format
        self._min_severity = min_severity.lower()
        self._file: TextIO = file if file is not None else sys.stdout
        self._ci_override = ci_override

        # Rich console is always created; no_color / force_terminal controlled
        # by the output format.
        self._console = Console(
            file=self._file,
            no_color=(output_format != OutputFormat.RICH),
            highlight=False,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def render(self, result: "object") -> int:  # ScanResult
        """Render *result* to the configured output stream.

        Parameters
        ----------
        result:
            A :class:`~contagious_scan.scanner.ScanResult` instance.

        Returns
        -------
        int
            Exit code: ``0`` (no findings), ``1`` (findings present),
            or ``2`` (scan errors).  Always ``0`` when *ci_override* is set.
        """
        if self._format == OutputFormat.JSON:
            self._render_json(result)
        elif self._format == OutputFormat.PLAIN:
            self._render_plain(result)
        else:
            self._render_rich(result)

        return self._exit_code(result)

    def render_to_string(self, result: "object") -> str:  # ScanResult
        """Render *result* to a string and return it.

        This is useful for capturing output in tests or programmatic usage.

        Parameters
        ----------
        result:
            A :class:`~contagious_scan.scanner.ScanResult` instance.

        Returns
        -------
        str
            Rendered output as a string.
        """
        buf = StringIO()
        reporter = Reporter(
            output_format=self._format,
            min_severity=self._min_severity,
            file=buf,
            ci_override=self._ci_override,
        )
        reporter.render(result)
        return buf.getvalue()

    # ------------------------------------------------------------------
    # Rich format
    # ------------------------------------------------------------------

    def _render_rich(self, result: "object") -> None:  # ScanResult
        """Render findings as a rich colour-coded terminal table."""
        findings = self._filtered_findings(result)
        errors: list[str] = getattr(result, "errors", [])
        repository: str = getattr(result, "repository", "unknown")
        scan_timestamp: str = getattr(result, "scan_timestamp", "")
        scanned_count: int = len(getattr(result, "scanned_files", []))
        elapsed: float = getattr(result, "elapsed_seconds", 0.0)

        # ---- Header panel ----
        by_sev = _group_by_severity(findings)
        summary_parts: list[str] = []
        for sev in ["critical", "high", "medium", "info"]:
            count = len(by_sev.get(sev, []))
            if count > 0:
                style = _SEVERITY_STYLE.get(sev, "white")
                emoji = _SEVERITY_EMOJI.get(sev, "")
                summary_parts.append(
                    f"[{style}]{emoji} {count} {sev.upper()}[/{style}]"
                )

        total = len(findings)
        if total == 0:
            header_text = (
                f"[bold green]✅ No findings[/bold green]  "
                f"│  {scanned_count} files scanned  "
                f"│  {elapsed:.2f}s"
            )
        else:
            sev_summary = "  ".join(summary_parts) if summary_parts else ""
            header_text = (
                f"[bold]contagious_scan[/bold]  "
                f"│  [bold]{total} finding{'s' if total != 1 else ''}[/bold]  "
                f"│  {sev_summary}  "
                f"│  {scanned_count} files scanned  "
                f"│  {elapsed:.2f}s"
            )

        self._console.print()
        self._console.print(
            Panel(
                header_text,
                title="[bold blue]contagious_scan[/bold blue]",
                subtitle=f"[dim]{scan_timestamp}[/dim]",
                border_style="blue",
                expand=False,
            )
        )

        # ---- Repository label ----
        self._console.print(
            f"  [dim]Repository:[/dim] [bold]{repository}[/bold]"
        )
        self._console.print()

        # ---- Errors (if any) ----
        if errors:
            self._console.print("[bold red]⚠ Scan Errors:[/bold red]")
            for err in errors:
                self._console.print(f"  [red]• {err}[/red]")
            self._console.print()

        if not findings:
            self._console.print(
                "[bold green]✅ No findings detected above the minimum severity threshold.[/bold green]"
            )
            self._console.print()
            return

        # ---- Findings table ----
        table = Table(
            show_header=True,
            header_style="bold cyan",
            box=box.ROUNDED,
            expand=False,
            show_lines=True,
        )
        table.add_column("#", style="dim", width=4, no_wrap=True)
        table.add_column("Severity", width=10, no_wrap=True)
        table.add_column("File", min_width=20, max_width=50)
        table.add_column("Line", width=6, no_wrap=True)
        table.add_column("Pattern ID", min_width=20, max_width=35)
        table.add_column("Description", min_width=30)
        table.add_column("Matched Text", min_width=20, max_width=40)

        for idx, finding in enumerate(findings, start=1):
            sev = finding.severity.lower()
            style = _SEVERITY_STYLE.get(sev, "white")
            emoji = _SEVERITY_EMOJI.get(sev, "")

            line_str = str(finding.line_number) if finding.line_number else "—"
            matched = _truncate_display(finding.matched_text, 80)
            description = _truncate_display(finding.description, 100)

            table.add_row(
                str(idx),
                Text(f"{emoji} {sev.upper()}", style=style),
                finding.file_path,
                line_str,
                finding.pattern_id,
                description,
                matched,
            )

        self._console.print(table)
        self._console.print()

        # ---- Remediation hints for critical findings ----
        critical_findings = [f for f in findings if f.severity == "critical"]
        if critical_findings:
            self._console.print(
                "[bold red]🔴 Critical Findings — Remediation Required:[/bold red]"
            )
            for f in critical_findings[:5]:  # show at most 5 remediations
                self._console.print(
                    f"  [dim]{f.pattern_id}[/dim] — {f.file_path}:{f.line_number}"
                )
                self._console.print(f"    [yellow]{f.remediation}[/yellow]")
            if len(critical_findings) > 5:
                self._console.print(
                    f"  [dim]... and {len(critical_findings) - 5} more critical findings.[/dim]"
                )
            self._console.print()

    # ------------------------------------------------------------------
    # JSON format
    # ------------------------------------------------------------------

    def _render_json(self, result: "object") -> None:  # ScanResult
        """Render findings as machine-readable JSON."""
        findings = self._filtered_findings(result)

        # Build the full dict from the result's to_dict() but override findings
        # with the filtered list so the JSON matches what the user sees.
        try:
            data = result.to_dict()  # type: ignore[union-attr]
        except AttributeError:
            data = {}

        # Override findings with filtered + serialised findings
        data["findings"] = [f.to_dict() for f in findings]
        data["total_findings"] = len(findings)
        data["min_severity_filter"] = self._min_severity

        # Recompute severity summary for filtered findings
        by_sev = _group_by_severity(findings)
        data["severity_summary"] = {
            sev: len(by_sev.get(sev, [])) for sev in ["critical", "high", "medium", "info"]
        }

        json_str = json.dumps(data, indent=2, ensure_ascii=False)
        print(json_str, file=self._file)

    # ------------------------------------------------------------------
    # Plain text format
    # ------------------------------------------------------------------

    def _render_plain(self, result: "object") -> None:  # ScanResult
        """Render findings as plain text with no ANSI codes."""
        findings = self._filtered_findings(result)
        errors: list[str] = getattr(result, "errors", [])
        repository: str = getattr(result, "repository", "unknown")
        scan_timestamp: str = getattr(result, "scan_timestamp", "")
        scanned_count: int = len(getattr(result, "scanned_files", []))
        elapsed: float = getattr(result, "elapsed_seconds", 0.0)
        total = len(findings)

        _p = self._file.write

        def line(text: str = "") -> None:
            _p(text + "\n")

        line("=" * 72)
        line("contagious_scan — Scan Report")
        line("=" * 72)
        line(f"Repository  : {repository}")
        line(f"Timestamp   : {scan_timestamp}")
        line(f"Files scanned: {scanned_count}")
        line(f"Elapsed     : {elapsed:.2f}s")
        line(f"Total findings (>= {self._min_severity}): {total}")

        by_sev = _group_by_severity(findings)
        for sev in ["critical", "high", "medium", "info"]:
            count = len(by_sev.get(sev, []))
            if count:
                line(f"  {sev.upper()}: {count}")

        if errors:
            line()
            line("ERRORS:")
            for err in errors:
                line(f"  [!] {err}")

        if not findings:
            line()
            line("No findings detected above the minimum severity threshold.")
            line("=" * 72)
            return

        line()
        line("-" * 72)
        line(f"{'#':<4} {'SEVERITY':<10} {'FILE':<35} {'LINE':<6} {'PATTERN ID':<30}")
        line("-" * 72)

        for idx, f in enumerate(findings, start=1):
            line_str = str(f.line_number) if f.line_number else "-"
            sev_str = f.severity.upper()
            file_str = _truncate_display(f.file_path, 34)
            pat_str = _truncate_display(f.pattern_id, 29)
            line(f"{idx:<4} {sev_str:<10} {file_str:<35} {line_str:<6} {pat_str}")

        line()
        line("=" * 72)
        line("FINDING DETAILS")
        line("=" * 72)

        for idx, f in enumerate(findings, start=1):
            line_str = str(f.line_number) if f.line_number else "-"
            line()
            line(f"[{idx}] {f.severity.upper()} — {f.file_path}:{line_str}")
            line(f"    Pattern  : {f.pattern_id}")
            line(f"    Desc     : {f.description}")
            line(f"    Match    : {_truncate_display(f.matched_text, 120)}")
            line(f"    Tags     : {', '.join(sorted(f.tags))}")
            line(f"    Remediate: {f.remediation}")

        line()
        line("=" * 72)

    # ------------------------------------------------------------------
    # Exit code logic
    # ------------------------------------------------------------------

    def _exit_code(self, result: "object") -> int:  # ScanResult
        """Compute the appropriate exit code for *result*.

        Parameters
        ----------
        result:
            A :class:`~contagious_scan.scanner.ScanResult` instance.

        Returns
        -------
        int
            ``EXIT_OK`` (0), ``EXIT_FINDINGS`` (1), or ``EXIT_ERROR`` (2).
            Always ``EXIT_OK`` when *ci_override* is set.
        """
        if self._ci_override:
            return EXIT_OK

        errors: list[str] = getattr(result, "errors", [])
        if errors and not getattr(result, "findings", None) and not getattr(result, "scanned_files", None):
            # Fatal scan error with no output at all
            return EXIT_ERROR

        findings = self._filtered_findings(result)
        if findings:
            return EXIT_FINDINGS

        if errors:
            return EXIT_ERROR

        return EXIT_OK

    def _filtered_findings(self, result: "object") -> list[Finding]:  # ScanResult
        """Return findings from *result* filtered to the minimum severity.

        Parameters
        ----------
        result:
            A :class:`~contagious_scan.scanner.ScanResult` instance.

        Returns
        -------
        list[Finding]
            Filtered and sorted findings.
        """
        all_findings: list[Finding] = getattr(result, "findings", [])
        return filter_findings_by_severity(all_findings, self._min_severity)


# ---------------------------------------------------------------------------
# Module-level helper functions
# ---------------------------------------------------------------------------


def render_findings(
    result: "object",  # ScanResult
    output_format: str | OutputFormat = OutputFormat.RICH,
    min_severity: str = "info",
    file: TextIO | None = None,
    ci_override: bool = False,
) -> int:
    """Convenience function to render a scan result and return the exit code.

    Parameters
    ----------
    result:
        A :class:`~contagious_scan.scanner.ScanResult` instance.
    output_format:
        Format string or ``OutputFormat`` enum value.
    min_severity:
        Minimum severity threshold.
    file:
        Output stream.  Defaults to ``sys.stdout``.
    ci_override:
        If ``True``, always return exit code ``0``.

    Returns
    -------
    int
        Exit code.
    """
    if isinstance(output_format, str):
        output_format = OutputFormat.from_string(output_format)

    reporter = Reporter(
        output_format=output_format,
        min_severity=min_severity,
        file=file,
        ci_override=ci_override,
    )
    return reporter.render(result)


def determine_exit_code(
    result: "object",  # ScanResult
    min_severity: str = "info",
    ci_override: bool = False,
) -> int:
    """Determine the exit code for a scan result without rendering output.

    Parameters
    ----------
    result:
        A :class:`~contagious_scan.scanner.ScanResult` instance.
    min_severity:
        Minimum severity threshold.
    ci_override:
        If ``True``, always return ``EXIT_OK``.

    Returns
    -------
    int
        ``EXIT_OK`` (0), ``EXIT_FINDINGS`` (1), or ``EXIT_ERROR`` (2).
    """
    if ci_override:
        return EXIT_OK

    errors: list[str] = getattr(result, "errors", [])
    all_findings: list[Finding] = getattr(result, "findings", [])
    filtered = filter_findings_by_severity(all_findings, min_severity)

    if filtered:
        return EXIT_FINDINGS

    if errors:
        return EXIT_ERROR

    return EXIT_OK


def _group_by_severity(findings: list[Finding]) -> dict[str, list[Finding]]:
    """Group findings by their severity string.

    Parameters
    ----------
    findings:
        List of findings to group.

    Returns
    -------
    dict[str, list[Finding]]
        Keys are severity strings; values are lists of findings.
    """
    grouped: dict[str, list[Finding]] = {}
    for f in findings:
        grouped.setdefault(f.severity.lower(), []).append(f)
    return grouped


def _truncate_display(text: str, max_len: int) -> str:
    """Truncate *text* for display purposes.

    Parameters
    ----------
    text:
        Input string to truncate.
    max_len:
        Maximum number of characters.

    Returns
    -------
    str
        Truncated string with ``'...'`` appended if truncation occurred.
    """
    text = text.strip()
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."
