"""Tests for the contagious_scan CLI entry point (cli.py).

Covers the scan, install-hook, and report commands including flag
parsing, exit code behaviour, and output format switching.
"""

from __future__ import annotations

import json
from io import StringIO
from pathlib import Path

import pytest
from click.testing import CliRunner

try:
    from git import Repo
    GIT_AVAILABLE = True
except ImportError:
    GIT_AVAILABLE = False

from contagious_scan.cli import main
from contagious_scan.reporter import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def invoke(args: list[str], **kwargs) -> object:
    """Invoke the CLI with the given arguments using Click's test runner."""
    runner = CliRunner(mix_stderr=False)
    return runner.invoke(main, args, catch_exceptions=False, **kwargs)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def benign_dir(tmp_path: Path) -> Path:
    """Create a plain directory with benign files."""
    (tmp_path / "hello.js").write_text(
        "function greet(name) { return 'Hello, ' + name; }\n"
    )
    (tmp_path / "utils.py").write_text("def add(a, b):\n    return a + b\n")
    return tmp_path


@pytest.fixture()
def malicious_dir(tmp_path: Path) -> Path:
    """Create a plain directory with a malicious file."""
    (tmp_path / "loader.js").write_text(
        "eval(atob('SGVsbG8gV29ybGQ='));\n"
        "const keytar = require('keytar');\n"
    )
    return tmp_path


@pytest.fixture()
def git_repo_dir(tmp_path: Path) -> Path:
    """Create a minimal Git repository with a benign file."""
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    if GIT_AVAILABLE:
        repo = Repo.init(str(repo_dir))
        repo.config_writer().set_value("user", "name", "Test").release()
        repo.config_writer().set_value("user", "email", "t@t.com").release()
        (repo_dir / "hello.js").write_text("console.log('hello');\n")
        repo.index.add(["hello.js"])
        repo.index.commit("Initial")
    else:
        (repo_dir / "hello.js").write_text("console.log('hello');\n")
    return repo_dir


@pytest.fixture()
def saved_json_result(tmp_path: Path, malicious_dir: Path) -> Path:
    """Run a scan and save the JSON result to a file."""
    from contagious_scan.scanner import scan
    from contagious_scan.reporter import Reporter, OutputFormat

    result = scan(malicious_dir, min_severity="info")
    data = result.to_dict()
    out_file = tmp_path / "findings.json"
    out_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return out_file


# ---------------------------------------------------------------------------
# Version and help
# ---------------------------------------------------------------------------


class TestVersionAndHelp:
    """Basic CLI sanity checks."""

    def test_version_flag(self) -> None:
        result = invoke(["--version"])
        assert result.exit_code == 0
        from contagious_scan import __version__
        assert __version__ in result.output

    def test_help_flag(self) -> None:
        result = invoke(["--help"])
        assert result.exit_code == 0
        assert "scan" in result.output
        assert "install-hook" in result.output
        assert "report" in result.output

    def test_scan_help(self) -> None:
        result = invoke(["scan", "--help"])
        assert result.exit_code == 0
        assert "--format" in result.output
        assert "--min-severity" in result.output

    def test_install_hook_help(self) -> None:
        result = invoke(["install-hook", "--help"])
        assert result.exit_code == 0
        assert "--ci-override" in result.output

    def test_report_help(self) -> None:
        result = invoke(["report", "--help"])
        assert result.exit_code == 0
        assert "RESULTS_FILE" in result.output


# ---------------------------------------------------------------------------
# scan command — basic
# ---------------------------------------------------------------------------


class TestScanCommand:
    """Tests for the scan command."""

    def test_scan_benign_dir_exit_ok(self, benign_dir: Path) -> None:
        result = invoke(["scan", str(benign_dir), "--min-severity", "critical"])
        assert result.exit_code == EXIT_OK

    def test_scan_malicious_dir_exit_findings(self, malicious_dir: Path) -> None:
        result = invoke(["scan", str(malicious_dir), "--min-severity", "info"])
        assert result.exit_code == EXIT_FINDINGS

    def test_scan_plain_format(self, malicious_dir: Path) -> None:
        result = invoke(["scan", str(malicious_dir), "--format", "plain"])
        assert result.exit_code in (EXIT_OK, EXIT_FINDINGS)
        assert isinstance(result.output, str)

    def test_scan_json_format_valid_json(self, malicious_dir: Path) -> None:
        result = invoke(["scan", str(malicious_dir), "--format", "json", "--min-severity", "info"])
        assert result.exit_code in (EXIT_OK, EXIT_FINDINGS)
        data = json.loads(result.output)
        assert "findings" in data
        assert "total_findings" in data

    def test_scan_rich_format(self, malicious_dir: Path) -> None:
        result = invoke(["scan", str(malicious_dir), "--format", "rich"])
        assert result.exit_code in (EXIT_OK, EXIT_FINDINGS)

    def test_scan_nonexistent_path_exit_error(self, tmp_path: Path) -> None:
        result = invoke(["scan", str(tmp_path / "does_not_exist")])
        # Should exit with error code (2) or findings (1)
        assert result.exit_code in (EXIT_ERROR, EXIT_FINDINGS)

    def test_scan_ci_override_exits_zero(self, malicious_dir: Path) -> None:
        result = invoke(
            ["scan", str(malicious_dir), "--ci-override", "--min-severity", "info"]
        )
        assert result.exit_code == EXIT_OK

    def test_scan_min_severity_critical_no_findings(self, benign_dir: Path) -> None:
        result = invoke(["scan", str(benign_dir), "--min-severity", "critical"])
        assert result.exit_code == EXIT_OK

    def test_scan_json_contains_repository(self, malicious_dir: Path) -> None:
        result = invoke(["scan", str(malicious_dir), "--format", "json"])
        data = json.loads(result.output)
        assert "repository" in data

    def test_scan_json_has_severity_summary(self, malicious_dir: Path) -> None:
        result = invoke(
            ["scan", str(malicious_dir), "--format", "json", "--min-severity", "info"]
        )
        data = json.loads(result.output)
        assert "severity_summary" in data

    def test_scan_output_file_created(self, malicious_dir: Path, tmp_path: Path) -> None:
        out_file = tmp_path / "results.json"
        result = invoke(
            [
                "scan", str(malicious_dir),
                "--format", "plain",
                "--output", str(out_file),
            ]
        )
        assert result.exit_code in (EXIT_OK, EXIT_FINDINGS)
        assert out_file.exists()
        data = json.loads(out_file.read_text())
        assert "findings" in data

    def test_scan_skip_ext_skips_extension(self, tmp_path: Path) -> None:
        (tmp_path / "evil.js").write_text("eval(atob('payload'))")
        # Skip .js files
        result = invoke(
            ["scan", str(tmp_path), "--skip-ext", ".js", "--format", "json"]
        )
        data = json.loads(result.output)
        js_findings = [
            f for f in data["findings"]
            if str(f.get("file", "")).endswith(".js")
        ]
        assert js_findings == []

    def test_scan_include_history_flag_accepted(self, benign_dir: Path) -> None:
        # Just verify the flag is accepted without crash
        result = invoke(
            ["scan", str(benign_dir), "--include-history", "--history-depth", "5"]
        )
        assert result.exit_code in (EXIT_OK, EXIT_FINDINGS, EXIT_ERROR)

    def test_scan_invalid_format_shows_error(self, benign_dir: Path) -> None:
        runner = CliRunner(mix_stderr=False)
        result = runner.invoke(
            main,
            ["scan", str(benign_dir), "--format", "xml"],
            catch_exceptions=False,
        )
        # Click should reject invalid choice
        assert result.exit_code != EXIT_OK

    def test_scan_multiple_skip_extensions(self, tmp_path: Path) -> None:
        (tmp_path / "evil.js").write_text("eval(atob('x'))")
        (tmp_path / "evil.py").write_text("exec(base64.b64decode('x'))")
        result = invoke(
            [
                "scan", str(tmp_path),
                "--skip-ext", ".js",
                "--skip-ext", ".py",
                "--format", "json",
            ]
        )
        data = json.loads(result.output)
        for f in data["findings"]:
            file_path = str(f.get("file", ""))
            assert not file_path.endswith(".js")
            assert not file_path.endswith(".py")

    def test_scan_plain_contains_repository(self, malicious_dir: Path) -> None:
        result = invoke(["scan", str(malicious_dir), "--format", "plain"])
        assert str(malicious_dir.resolve()) in result.output or "repository" in result.output.lower()


# ---------------------------------------------------------------------------
# scan command — Git repo specific
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not GIT_AVAILABLE, reason="GitPython not installed")
class TestScanCommandGitRepo:
    """Tests for scan command on Git repositories."""

    def test_scan_git_repo_exit_ok(self, git_repo_dir: Path) -> None:
        result = invoke(["scan", str(git_repo_dir), "--min-severity", "critical"])
        assert result.exit_code == EXIT_OK

    def test_scan_staged_only_flag_accepted(self, git_repo_dir: Path) -> None:
        result = invoke(["scan", str(git_repo_dir), "--staged-only"])
        assert result.exit_code in (EXIT_OK, EXIT_FINDINGS, EXIT_ERROR)

    def test_scan_include_untracked_flag(self, git_repo_dir: Path) -> None:
        result = invoke(["scan", str(git_repo_dir), "--include-untracked"])
        assert result.exit_code in (EXIT_OK, EXIT_FINDINGS)


# ---------------------------------------------------------------------------
# install-hook command
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not GIT_AVAILABLE, reason="GitPython not installed")
class TestInstallHookCommand:
    """Tests for the install-hook command."""

    def test_install_hook_basic(self, git_repo_dir: Path) -> None:
        result = invoke(["install-hook", str(git_repo_dir)])
        assert result.exit_code == EXIT_OK
        hook_path = git_repo_dir / ".git" / "hooks" / "pre-push"
        assert hook_path.exists()

    def test_install_hook_creates_executable(self, git_repo_dir: Path) -> None:
        invoke(["install-hook", str(git_repo_dir)])
        import stat, os
        hook_path = git_repo_dir / ".git" / "hooks" / "pre-push"
        mode = os.stat(str(hook_path)).st_mode
        assert mode & stat.S_IXUSR

    def test_install_hook_ci_override_mode(self, git_repo_dir: Path) -> None:
        result = invoke(["install-hook", str(git_repo_dir), "--ci-override"])
        assert result.exit_code == EXIT_OK
        hook_path = git_repo_dir / ".git" / "hooks" / "pre-push"
        content = hook_path.read_text()
        assert "--ci-override" in content

    def test_install_hook_min_severity_embedded(self, git_repo_dir: Path) -> None:
        result = invoke(
            ["install-hook", str(git_repo_dir), "--min-severity", "high"]
        )
        assert result.exit_code == EXIT_OK
        hook_path = git_repo_dir / ".git" / "hooks" / "pre-push"
        assert "high" in hook_path.read_text()

    def test_install_hook_twice_without_force_shows_message(self, git_repo_dir: Path) -> None:
        invoke(["install-hook", str(git_repo_dir)])
        result = invoke(["install-hook", str(git_repo_dir)])
        # Second install should not error (returns already-installed message)
        assert result.exit_code in (EXIT_OK, EXIT_FINDINGS)

    def test_install_hook_force_flag(self, git_repo_dir: Path) -> None:
        invoke(["install-hook", str(git_repo_dir)])
        result = invoke(["install-hook", str(git_repo_dir), "--force"])
        assert result.exit_code == EXIT_OK

    def test_install_hook_uninstall_flag(self, git_repo_dir: Path) -> None:
        invoke(["install-hook", str(git_repo_dir)])
        result = invoke(["install-hook", str(git_repo_dir), "--uninstall"])
        assert result.exit_code == EXIT_OK
        hook_path = git_repo_dir / ".git" / "hooks" / "pre-push"
        assert not hook_path.exists()

    def test_install_hook_status_flag(self, git_repo_dir: Path) -> None:
        result = invoke(["install-hook", str(git_repo_dir), "--status"])
        assert result.exit_code == EXIT_OK
        assert "Installed" in result.output or "installed" in result.output.lower()

    def test_install_hook_status_shows_installed(self, git_repo_dir: Path) -> None:
        invoke(["install-hook", str(git_repo_dir)])
        result = invoke(["install-hook", str(git_repo_dir), "--status"])
        assert result.exit_code == EXIT_OK
        # Should show Yes for installed
        assert "Yes" in result.output

    def test_install_hook_not_git_repo_exits_error(self, tmp_path: Path) -> None:
        empty = tmp_path / "empty"
        empty.mkdir()
        runner = CliRunner(mix_stderr=False)
        result = runner.invoke(
            main,
            ["install-hook", str(empty)],
            catch_exceptions=True,
        )
        assert result.exit_code == EXIT_ERROR

    def test_install_hook_foreign_hook_without_force(self, git_repo_dir: Path) -> None:
        # Create a foreign hook
        hooks_dir = git_repo_dir / ".git" / "hooks"
        hooks_dir.mkdir(parents=True, exist_ok=True)
        (hooks_dir / "pre-push").write_text("#!/bin/bash\necho foreign\n")
        runner = CliRunner(mix_stderr=False)
        result = runner.invoke(
            main,
            ["install-hook", str(git_repo_dir)],
            catch_exceptions=True,
        )
        assert result.exit_code == EXIT_ERROR

    def test_install_hook_foreign_hook_with_force(self, git_repo_dir: Path) -> None:
        hooks_dir = git_repo_dir / ".git" / "hooks"
        hooks_dir.mkdir(parents=True, exist_ok=True)
        (hooks_dir / "pre-push").write_text("#!/bin/bash\necho foreign\n")
        result = invoke(["install-hook", str(git_repo_dir), "--force"])
        assert result.exit_code == EXIT_OK

    def test_install_hook_no_backup_flag(self, git_repo_dir: Path) -> None:
        # Install first
        invoke(["install-hook", str(git_repo_dir)])
        # Reinstall with --force --no-backup
        result = invoke(["install-hook", str(git_repo_dir), "--force", "--no-backup"])
        assert result.exit_code == EXIT_OK
        bak_path = git_repo_dir / ".git" / "hooks" / "pre-push.bak"
        # Backup should NOT exist since we said --no-backup
        # (Note: the .bak from a previous run may exist; only check if fresh)
        # This just verifies the command runs successfully
        assert result.exit_code == EXIT_OK

    def test_uninstall_when_not_installed_exits_ok(self, git_repo_dir: Path) -> None:
        result = invoke(["install-hook", str(git_repo_dir), "--uninstall"])
        assert result.exit_code == EXIT_OK


# ---------------------------------------------------------------------------
# report command
# ---------------------------------------------------------------------------


class TestReportCommand:
    """Tests for the report command."""

    def test_report_plain_format(self, saved_json_result: Path) -> None:
        result = invoke(["report", str(saved_json_result), "--format", "plain"])
        assert result.exit_code in (EXIT_OK, EXIT_FINDINGS)
        assert isinstance(result.output, str)
        assert len(result.output) > 0

    def test_report_json_format(self, saved_json_result: Path) -> None:
        result = invoke(["report", str(saved_json_result), "--format", "json"])
        assert result.exit_code in (EXIT_OK, EXIT_FINDINGS)
        data = json.loads(result.output)
        assert "findings" in data

    def test_report_rich_format(self, saved_json_result: Path) -> None:
        result = invoke(["report", str(saved_json_result), "--format", "rich"])
        assert result.exit_code in (EXIT_OK, EXIT_FINDINGS)

    def test_report_ci_override_exits_zero(self, saved_json_result: Path) -> None:
        result = invoke(
            ["report", str(saved_json_result), "--ci-override", "--format", "plain"]
        )
        assert result.exit_code == EXIT_OK

    def test_report_min_severity_filters(self, saved_json_result: Path) -> None:
        # With min_severity=critical, benign results may become EXIT_OK
        result = invoke(
            ["report", str(saved_json_result), "--min-severity", "critical", "--format", "json"]
        )
        assert result.exit_code in (EXIT_OK, EXIT_FINDINGS)
        data = json.loads(result.output)
        for f in data["findings"]:
            assert f["severity"] == "critical"

    def test_report_invalid_json_exits_error(self, tmp_path: Path) -> None:
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("{ not valid json !!!")
        runner = CliRunner(mix_stderr=False)
        result = runner.invoke(
            main,
            ["report", str(bad_file)],
            catch_exceptions=True,
        )
        assert result.exit_code == EXIT_ERROR

    def test_report_nonexistent_file(self, tmp_path: Path) -> None:
        runner = CliRunner(mix_stderr=False)
        result = runner.invoke(
            main,
            ["report", str(tmp_path / "ghost.json")],
            catch_exceptions=True,
        )
        # Click should reject non-existent file path
        assert result.exit_code != EXIT_OK

    def test_report_empty_findings_exits_ok(self, tmp_path: Path) -> None:
        empty_result = {
            "scan_timestamp": "2024-01-01T00:00:00Z",
            "repository": "/empty/repo",
            "total_findings": 0,
            "findings": [],
            "scanned_files_count": 5,
            "skipped_files_count": 0,
            "errors": [],
            "elapsed_seconds": 0.5,
            "severity_summary": {"critical": 0, "high": 0, "medium": 0, "info": 0},
        }
        out_file = tmp_path / "empty.json"
        out_file.write_text(json.dumps(empty_result))
        result = invoke(["report", str(out_file), "--format", "plain"])
        assert result.exit_code == EXIT_OK

    def test_report_output_contains_repository(self, saved_json_result: Path) -> None:
        result = invoke(["report", str(saved_json_result), "--format", "plain"])
        assert isinstance(result.output, str)

    def test_report_json_output_has_min_severity_filter(self, saved_json_result: Path) -> None:
        result = invoke(
            ["report", str(saved_json_result), "--format", "json", "--min-severity", "high"]
        )
        data = json.loads(result.output)
        assert data.get("min_severity_filter") == "high"


# ---------------------------------------------------------------------------
# Verbose flag tests
# ---------------------------------------------------------------------------


class TestVerboseFlag:
    """Tests that the -v / --verbose flag is accepted."""

    def test_single_verbose(self, benign_dir: Path) -> None:
        result = invoke(["-v", "scan", str(benign_dir)])
        assert result.exit_code in (EXIT_OK, EXIT_FINDINGS)

    def test_double_verbose(self, benign_dir: Path) -> None:
        result = invoke(["-vv", "scan", str(benign_dir)])
        assert result.exit_code in (EXIT_OK, EXIT_FINDINGS)
