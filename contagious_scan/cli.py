"""Click-based CLI entry point for contagious_scan.

Provides three top-level commands:

- ``scan``         : Audit a local or remote Git repository for supply chain
                     attack indicators.
- ``install-hook`` : Write and activate a Git pre-push hook into a repository.
- ``report``       : Re-render a previously saved JSON scan result.

Typical usage::

    contagious-scan scan /path/to/repo
    contagious-scan scan . --format json --min-severity high
    contagious-scan scan https://github.com/org/repo --remote
    contagious-scan install-hook /path/to/repo
    contagious-scan install-hook . --ci-override
    contagious-scan report findings.json --format rich
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.logging import RichHandler

from contagious_scan import __version__
from contagious_scan.hook_installer import (
    ExistingHookError,
    HookInstaller,
    HookInstallerError,
    NotAGitRepoError as HookNotAGitRepoError,
    get_hook_status,
    install_hook,
    is_hook_installed,
    uninstall_hook,
)
from contagious_scan.reporter import (
    EXIT_ERROR,
    EXIT_FINDINGS,
    EXIT_OK,
    OutputFormat,
    Reporter,
    determine_exit_code,
    render_findings,
)
from contagious_scan.scanner import ScanConfig, Scanner, ScanResult

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

_VERBOSITY_TO_LEVEL: dict[int, int] = {
    0: logging.WARNING,
    1: logging.INFO,
    2: logging.DEBUG,
}


def _configure_logging(verbosity: int) -> None:
    """Configure the root logger based on the *verbosity* count.

    Parameters
    ----------
    verbosity:
        Number of ``-v`` flags passed on the command line.
        0 = WARNING, 1 = INFO, 2+ = DEBUG.
    """
    level = _VERBOSITY_TO_LEVEL.get(verbosity, logging.DEBUG)
    logging.basicConfig(
        level=level,
        format="%(message)s",
        handlers=[
            RichHandler(
                rich_tracebacks=True,
                show_time=False,
                show_path=(verbosity >= 2),
            )
        ],
    )


# ---------------------------------------------------------------------------
# Shared Rich console (for non-reporter output)
# ---------------------------------------------------------------------------

_console = Console(stderr=True)


def _error(msg: str) -> None:
    """Print an error message to stderr using Rich."""
    _console.print(f"[bold red]Error:[/bold red] {msg}", highlight=False)


def _warn(msg: str) -> None:
    """Print a warning message to stderr using Rich."""
    _console.print(f"[bold yellow]Warning:[/bold yellow] {msg}", highlight=False)


def _info(msg: str) -> None:
    """Print an informational message to stderr using Rich."""
    _console.print(f"[dim]{msg}[/dim]", highlight=False)


# ---------------------------------------------------------------------------
# CLI group
# ---------------------------------------------------------------------------


@click.group()
@click.version_option(version=__version__, prog_name="contagious-scan")
@click.option(
    "-v",
    "--verbose",
    count=True,
    help="Increase verbosity. Use -v for INFO, -vv for DEBUG.",
)
@click.pass_context
def main(ctx: click.Context, verbose: int) -> None:
    """contagious-scan: audit Git repositories for Contagious Interview supply chain attack indicators.

    Detects BeaverTail / InvisibleFerret RAT payloads, obfuscated loaders,
    malicious lifecycle hooks, and CI/CD poisoning patterns.

    \b
    Examples:
        contagious-scan scan .
        contagious-scan scan . --format json --min-severity high
        contagious-scan scan https://github.com/org/repo --remote
        contagious-scan install-hook .
        contagious-scan report findings.json
    """
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    _configure_logging(verbose)


# ---------------------------------------------------------------------------
# scan command
# ---------------------------------------------------------------------------


@main.command("scan")
@click.argument(
    "target",
    default=".",
    metavar="TARGET",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["rich", "json", "plain"], case_sensitive=False),
    default="rich",
    show_default=True,
    help="Output format: rich (coloured table), json, or plain text.",
)
@click.option(
    "--min-severity",
    type=click.Choice(["critical", "high", "medium", "info"], case_sensitive=False),
    default="info",
    show_default=True,
    help="Minimum severity level to report and include in exit code logic.",
)
@click.option(
    "--staged-only",
    is_flag=True,
    default=False,
    help="Only scan files staged in the Git index (pre-push hook mode).",
)
@click.option(
    "--remote",
    is_flag=True,
    default=False,
    help="Treat TARGET as a remote URL; clone it before scanning.",
)
@click.option(
    "--include-history",
    is_flag=True,
    default=False,
    help="Also scan files from commit history (up to --history-depth commits).",
)
@click.option(
    "--history-depth",
    type=click.IntRange(min=1),
    default=20,
    show_default=True,
    help="Number of historical commits to inspect (requires --include-history).",
)
@click.option(
    "--include-untracked",
    is_flag=True,
    default=False,
    help="Also scan untracked (new) files not yet committed.",
)
@click.option(
    "--clone-depth",
    type=click.IntRange(min=1),
    default=None,
    help="Shallow clone depth for remote scans (omit for full clone).",
)
@click.option(
    "--branch",
    default=None,
    metavar="BRANCH",
    help="Branch to scan or clone. Defaults to the repository default branch.",
)
@click.option(
    "--output",
    "-o",
    "output_file",
    default=None,
    metavar="FILE",
    help="Save JSON scan results to FILE in addition to console output.",
    type=click.Path(dir_okay=False, writable=True),
)
@click.option(
    "--ci-override",
    is_flag=True,
    default=False,
    help="Always exit 0 even when findings are present (for CI pipelines).",
)
@click.option(
    "--skip-ext",
    "skip_extensions",
    multiple=True,
    metavar="EXT",
    help="File extensions to skip (e.g. --skip-ext .md --skip-ext .txt).",
)
@click.pass_context
def cmd_scan(
    ctx: click.Context,
    target: str,
    output_format: str,
    min_severity: str,
    staged_only: bool,
    remote: bool,
    include_history: bool,
    history_depth: int,
    include_untracked: bool,
    clone_depth: Optional[int],
    branch: Optional[str],
    output_file: Optional[str],
    ci_override: bool,
    skip_extensions: tuple[str, ...],
) -> None:
    """Scan a local repository or remote URL for supply chain attack indicators.

    TARGET can be:

    \b
      - A local directory path (default: current directory)
      - A remote Git URL when --remote flag is used

    \b
    Examples:
        contagious-scan scan .
        contagious-scan scan /path/to/repo --min-severity high
        contagious-scan scan . --staged-only
        contagious-scan scan https://github.com/org/pkg --remote
        contagious-scan scan . --format json -o results.json
    """
    verbose: int = ctx.obj.get("verbose", 0)

    # Normalise skip extensions (ensure leading dot)
    normalised_skip: frozenset[str] = frozenset(
        ext if ext.startswith(".") else f".{ext}"
        for ext in skip_extensions
    )

    # Build ScanConfig
    try:
        config = ScanConfig(
            target_path=Path(target) if not remote else Path("."),
            remote_url=target if remote else None,
            staged_only=staged_only,
            include_history=include_history,
            history_depth=history_depth,
            min_severity=min_severity.lower(),
            include_untracked=include_untracked,
            clone_depth=clone_depth,
            branch=branch,
            skip_extensions=normalised_skip,
        )
    except ValueError as exc:
        _error(str(exc))
        sys.exit(EXIT_ERROR)

    # Progress callback for verbose mode
    progress_cb = None
    if verbose >= 1:
        def progress_cb(file_path: str, done: int, total: int) -> None:
            _info(f"[{done}/{total}] {file_path}")

    # Run scan
    if verbose >= 1:
        _info(
            f"Scanning {'remote: ' + target if remote else target!r} "
            f"[min-severity={min_severity}, format={output_format}]"
        )

    scanner = Scanner(config, progress_callback=progress_cb)
    result: ScanResult = scanner.run()

    # Render to stdout
    fmt = OutputFormat.from_string(output_format)
    reporter = Reporter(
        output_format=fmt,
        min_severity=min_severity,
        file=sys.stdout,
        ci_override=ci_override,
    )
    exit_code = reporter.render(result)

    # Optionally save JSON output to file
    if output_file:
        _save_json_result(result, output_file, min_severity)

    sys.exit(exit_code)


def _save_json_result(
    result: ScanResult,
    output_file: str,
    min_severity: str,
) -> None:
    """Serialise *result* as JSON and write to *output_file*.

    Parameters
    ----------
    result:
        The scan result to serialise.
    output_file:
        Destination file path.
    min_severity:
        Minimum severity filter applied before saving.
    """
    from contagious_scan.detectors import filter_findings_by_severity

    try:
        data = result.to_dict()
        # Filter findings to respect min_severity
        filtered = filter_findings_by_severity(result.findings, min_severity)
        data["findings"] = [f.to_dict() for f in filtered]
        data["total_findings"] = len(filtered)
        data["min_severity_filter"] = min_severity

        with open(output_file, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
        _info(f"Scan results saved to '{output_file}'")
    except OSError as exc:
        _warn(f"Could not save results to '{output_file}': {exc}")
    except Exception as exc:  # noqa: BLE001
        _warn(f"Unexpected error saving results: {exc}")


# ---------------------------------------------------------------------------
# install-hook command
# ---------------------------------------------------------------------------


@main.command("install-hook")
@click.argument(
    "repo_path",
    default=".",
    metavar="REPO_PATH",
)
@click.option(
    "--ci-override",
    is_flag=True,
    default=False,
    help=(
        "Install the hook in non-blocking mode: findings are reported "
        "but the push is never blocked. Useful for CI pipelines."
    ),
)
@click.option(
    "--min-severity",
    type=click.Choice(["critical", "high", "medium", "info"], case_sensitive=False),
    default="critical",
    show_default=True,
    help="Minimum severity level that triggers a blocked push.",
)
@click.option(
    "--force",
    is_flag=True,
    default=False,
    help="Overwrite any existing pre-push hook (creates a .bak backup first).",
)
@click.option(
    "--no-backup",
    is_flag=True,
    default=False,
    help="Do not create a .bak backup when overwriting an existing hook.",
)
@click.option(
    "--uninstall",
    is_flag=True,
    default=False,
    help="Remove the contagious_scan pre-push hook instead of installing it.",
)
@click.option(
    "--status",
    "show_status",
    is_flag=True,
    default=False,
    help="Show the current hook installation status and exit.",
)
@click.pass_context
def cmd_install_hook(
    ctx: click.Context,
    repo_path: str,
    ci_override: bool,
    min_severity: str,
    force: bool,
    no_backup: bool,
    uninstall: bool,
    show_status: bool,
) -> None:
    """Install (or manage) the Git pre-push hook in a repository.

    REPO_PATH is the path to the Git repository. Defaults to the current
    directory.

    The hook runs 'contagious-scan scan --staged-only' before each push
    and blocks the push when findings at or above MIN_SEVERITY are detected.

    \b
    Examples:
        contagious-scan install-hook .
        contagious-scan install-hook /path/to/repo --min-severity high
        contagious-scan install-hook . --ci-override
        contagious-scan install-hook . --force
        contagious-scan install-hook . --uninstall
        contagious-scan install-hook . --status
    """
    console = Console()  # stdout console for hook installer output

    # ------------------------------------------------------------------
    # Status mode
    # ------------------------------------------------------------------
    if show_status:
        try:
            status = get_hook_status(repo_path)
        except HookNotAGitRepoError as exc:
            _error(str(exc))
            sys.exit(EXIT_ERROR)
        except Exception as exc:  # noqa: BLE001
            _error(f"Could not retrieve hook status: {exc}")
            sys.exit(EXIT_ERROR)

        console.print()
        console.print("[bold blue]contagious_scan pre-push hook status[/bold blue]")
        console.print(f"  Repository  : {status.get('repo_path', repo_path)}")
        console.print(f"  Hooks dir   : {status.get('hook_path', '')}")
        console.print(f"  Installed   : {_bool_icon(status.get('installed', False))}")
        console.print(f"  Our hook    : {_bool_icon(status.get('our_hook', False))}")
        console.print(f"  Executable  : {_bool_icon(status.get('hook_executable', False))}")
        console.print(f"  CI override : {_bool_icon(status.get('ci_override', False))}")
        console.print(f"  Min severity: {status.get('min_severity', 'N/A')}")
        console.print()
        sys.exit(EXIT_OK)

    # ------------------------------------------------------------------
    # Uninstall mode
    # ------------------------------------------------------------------
    if uninstall:
        try:
            result = uninstall_hook(repo_path)
        except HookNotAGitRepoError as exc:
            _error(str(exc))
            sys.exit(EXIT_ERROR)
        except HookInstallerError as exc:
            _error(str(exc))
            sys.exit(EXIT_ERROR)
        except Exception as exc:  # noqa: BLE001
            _error(f"Unexpected error during uninstall: {exc}")
            sys.exit(EXIT_ERROR)

        if result.success:
            console.print(f"[bold green]{result.message}[/bold green]")
            sys.exit(EXIT_OK)
        else:
            console.print(f"[bold yellow]{result.message}[/bold yellow]")
            sys.exit(EXIT_FINDINGS)

    # ------------------------------------------------------------------
    # Install mode
    # ------------------------------------------------------------------
    try:
        result = install_hook(
            repo_path=repo_path,
            ci_override=ci_override,
            min_severity=min_severity.lower(),
            force=force,
            backup=not no_backup,
        )
    except HookNotAGitRepoError as exc:
        _error(str(exc))
        sys.exit(EXIT_ERROR)
    except ExistingHookError as exc:
        _error(
            f"{exc}\n"
            "Use --force to overwrite it (a .bak backup will be created)."
        )
        sys.exit(EXIT_ERROR)
    except HookInstallerError as exc:
        _error(str(exc))
        sys.exit(EXIT_ERROR)
    except Exception as exc:  # noqa: BLE001
        _error(f"Unexpected error during hook installation: {exc}")
        sys.exit(EXIT_ERROR)

    if result.success:
        console.print(f"[bold green]{result.message}[/bold green]")
        console.print()
        console.print(
            "  The hook will run [bold]contagious-scan scan --staged-only[/bold] "
            "before each push."
        )
        mode_desc = (
            "[yellow]CI override mode — findings will NOT block pushes.[/yellow]"
            if ci_override
            else f"[red]Pushes will be blocked if {min_severity.upper()} findings are detected.[/red]"
        )
        console.print(f"  {mode_desc}")
        console.print()
        console.print(
            "  To uninstall: "
            "[dim]contagious-scan install-hook . --uninstall[/dim]"
        )
        sys.exit(EXIT_OK)
    else:
        console.print(f"[bold yellow]{result.message}[/bold yellow]")
        sys.exit(EXIT_FINDINGS)


def _bool_icon(value: object) -> str:
    """Return a coloured tick or cross for a boolean status value.

    Parameters
    ----------
    value:
        Truthy or falsy value.

    Returns
    -------
    str
        Rich-markup string with a coloured icon.
    """
    if value:
        return "[bold green]✔ Yes[/bold green]"
    return "[bold red]✘ No[/bold red]"


# ---------------------------------------------------------------------------
# report command
# ---------------------------------------------------------------------------


@main.command("report")
@click.argument(
    "results_file",
    type=click.Path(exists=True, file_okay=True, dir_okay=False, readable=True),
    metavar="RESULTS_FILE",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["rich", "json", "plain"], case_sensitive=False),
    default="rich",
    show_default=True,
    help="Output format for re-rendering the saved scan result.",
)
@click.option(
    "--min-severity",
    type=click.Choice(["critical", "high", "medium", "info"], case_sensitive=False),
    default="info",
    show_default=True,
    help="Minimum severity level to include in the report.",
)
@click.option(
    "--ci-override",
    is_flag=True,
    default=False,
    help="Always exit 0 even when findings are present.",
)
@click.pass_context
def cmd_report(
    ctx: click.Context,
    results_file: str,
    output_format: str,
    min_severity: str,
    ci_override: bool,
) -> None:
    """Re-render a previously saved JSON scan result.

    RESULTS_FILE must be a JSON file produced by 'contagious-scan scan ... -o FILE'
    or by piping 'contagious-scan scan ... --format json' to a file.

    \b
    Examples:
        contagious-scan report findings.json
        contagious-scan report findings.json --format plain
        contagious-scan report findings.json --min-severity high
    """
    # Load and parse the JSON file
    try:
        raw_text = Path(results_file).read_text(encoding="utf-8")
        data = json.loads(raw_text)
    except (OSError, PermissionError) as exc:
        _error(f"Cannot read '{results_file}': {exc}")
        sys.exit(EXIT_ERROR)
    except json.JSONDecodeError as exc:
        _error(f"Invalid JSON in '{results_file}': {exc}")
        sys.exit(EXIT_ERROR)

    # Reconstruct a ScanResult-like object from the JSON data
    result = _reconstruct_scan_result(data, results_file)
    if result is None:
        sys.exit(EXIT_ERROR)

    # Render
    fmt = OutputFormat.from_string(output_format)
    reporter = Reporter(
        output_format=fmt,
        min_severity=min_severity,
        file=sys.stdout,
        ci_override=ci_override,
    )
    exit_code = reporter.render(result)
    sys.exit(exit_code)


def _reconstruct_scan_result(
    data: dict,
    source_file: str,
) -> Optional["ScanResult"]:
    """Reconstruct a :class:`~contagious_scan.scanner.ScanResult` from a JSON dict.

    Parameters
    ----------
    data:
        Parsed JSON dictionary from a saved scan result file.
    source_file:
        Path of the source file (used in error messages).

    Returns
    -------
    ScanResult or None
        Reconstructed result, or ``None`` if the data is malformed.
    """
    from contagious_scan.detectors import Finding

    try:
        raw_findings = data.get("findings", [])
        if not isinstance(raw_findings, list):
            _error(f"'findings' field in '{source_file}' is not a list.")
            return None

        findings: list[Finding] = []
        for raw in raw_findings:
            if not isinstance(raw, dict):
                continue
            try:
                finding = Finding(
                    severity=raw.get("severity", "info"),
                    file_path=raw.get("file", ""),
                    line_number=int(raw.get("line", 0)),
                    pattern_id=raw.get("pattern_id", "UNKNOWN"),
                    description=raw.get("description", ""),
                    matched_text=raw.get("matched_text", ""),
                    remediation=raw.get("remediation", ""),
                    tags=frozenset(raw.get("tags", [])),
                )
                findings.append(finding)
            except (TypeError, ValueError):
                # Skip malformed individual findings
                continue

        # Build a minimal ScanResult
        config = ScanConfig(target_path=".")
        result = ScanResult(
            repository=data.get("repository", source_file),
            scan_timestamp=data.get("scan_timestamp", ""),
            findings=findings,
            scanned_files=[
                f"{data.get('scanned_files_count', len(findings))} files"
            ],
            skipped_files=[
                f"{data.get('skipped_files_count', 0)} files"
            ],
            errors=data.get("errors", []),
            config=config,
            elapsed_seconds=float(data.get("elapsed_seconds", 0.0)),
        )
        return result

    except Exception as exc:  # noqa: BLE001
        _error(f"Failed to parse scan result from '{source_file}': {exc}")
        return None


# ---------------------------------------------------------------------------
# Entry point guard
# ---------------------------------------------------------------------------

if __name__ == "__main__":  # pragma: no cover
    main()
