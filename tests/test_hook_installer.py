"""Tests for contagious_scan.hook_installer module.

Verifies hook installation, uninstallation, status reporting, and
script content generation.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

try:
    from git import Repo
    GIT_AVAILABLE = True
except ImportError:
    GIT_AVAILABLE = False

from contagious_scan.hook_installer import (
    ExistingHookError,
    HookInstaller,
    HookInstallerError,
    InstallResult,
    NotAGitRepoError,
    _HOOK_MARKER,
    get_hook_status,
    install_hook,
    is_hook_installed,
    uninstall_hook,
)

pytestmark = pytest.mark.skipif(
    not GIT_AVAILABLE, reason="GitPython not installed"
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def git_repo(tmp_path: Path) -> Repo:
    """Initialise a minimal Git repository."""
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    repo = Repo.init(str(repo_dir))
    repo.config_writer().set_value("user", "name", "Test").release()
    repo.config_writer().set_value("user", "email", "t@t.com").release()
    return repo


@pytest.fixture()
def repo_path(git_repo: Repo) -> Path:
    """Return the working tree path of the test repo."""
    return Path(git_repo.working_tree_dir)


@pytest.fixture()
def installer(repo_path: Path) -> HookInstaller:
    """Return a HookInstaller for the test repo."""
    return HookInstaller(repo_path=repo_path)


# ---------------------------------------------------------------------------
# HookInstaller basic tests
# ---------------------------------------------------------------------------


class TestHookInstallerInit:
    """Tests for HookInstaller initialisation."""

    def test_creates_installer(self, repo_path: Path) -> None:
        installer = HookInstaller(repo_path=repo_path)
        assert installer is not None

    def test_hooks_dir_is_path(self, installer: HookInstaller) -> None:
        assert isinstance(installer.hooks_dir, Path)

    def test_hook_path_is_pre_push(self, installer: HookInstaller) -> None:
        assert installer.hook_path.name == "pre-push"

    def test_hook_path_inside_hooks_dir(self, installer: HookInstaller) -> None:
        assert installer.hook_path.parent == installer.hooks_dir

    def test_not_git_repo_raises(self, tmp_path: Path) -> None:
        empty = tmp_path / "empty"
        empty.mkdir()
        with pytest.raises(NotAGitRepoError):
            HookInstaller(repo_path=empty)


# ---------------------------------------------------------------------------
# is_installed / has_existing_hook
# ---------------------------------------------------------------------------


class TestHookInstalledCheck:
    """Tests for is_installed and has_existing_hook."""

    def test_not_installed_initially(self, installer: HookInstaller) -> None:
        assert installer.is_installed() is False

    def test_no_existing_hook_initially(self, installer: HookInstaller) -> None:
        assert installer.has_existing_hook() is False

    def test_is_installed_after_install(self, installer: HookInstaller) -> None:
        installer.install()
        assert installer.is_installed() is True

    def test_has_existing_hook_for_foreign_hook(self, installer: HookInstaller) -> None:
        # Write a hook not managed by us
        installer.hooks_dir.mkdir(parents=True, exist_ok=True)
        installer.hook_path.write_text("#!/bin/bash\necho hello\n")
        assert installer.has_existing_hook() is True
        assert installer.is_installed() is False

    def test_is_installed_checks_marker(self, installer: HookInstaller) -> None:
        installer.hooks_dir.mkdir(parents=True, exist_ok=True)
        installer.hook_path.write_text(f"#!/bin/bash\n{_HOOK_MARKER}\necho hi\n")
        assert installer.is_installed() is True


# ---------------------------------------------------------------------------
# install() tests
# ---------------------------------------------------------------------------


class TestHookInstall:
    """Tests for HookInstaller.install."""

    def test_install_returns_install_result(self, installer: HookInstaller) -> None:
        result = installer.install()
        assert isinstance(result, InstallResult)

    def test_install_success(self, installer: HookInstaller) -> None:
        result = installer.install()
        assert result.success is True

    def test_install_creates_hook_file(self, installer: HookInstaller) -> None:
        installer.install()
        assert installer.hook_path.exists()

    def test_install_makes_hook_executable(self, installer: HookInstaller) -> None:
        installer.install()
        mode = os.stat(str(installer.hook_path)).st_mode
        assert mode & stat.S_IXUSR, "Hook must be user-executable"

    def test_install_hook_contains_marker(self, installer: HookInstaller) -> None:
        installer.install()
        content = installer.hook_path.read_text(encoding="utf-8")
        assert _HOOK_MARKER in content

    def test_install_hook_is_bash_script(self, installer: HookInstaller) -> None:
        installer.install()
        content = installer.hook_path.read_text(encoding="utf-8")
        assert content.startswith("#!/usr/bin/env bash")

    def test_install_hook_contains_contagious_scan_command(self, installer: HookInstaller) -> None:
        installer.install()
        content = installer.hook_path.read_text(encoding="utf-8")
        assert "contagious-scan" in content

    def test_install_hook_contains_staged_only_flag(self, installer: HookInstaller) -> None:
        installer.install()
        content = installer.hook_path.read_text(encoding="utf-8")
        assert "--staged-only" in content

    def test_install_creates_hooks_dir_if_missing(self, installer: HookInstaller) -> None:
        # hooks dir may or may not exist; ensure it's created
        hooks_dir = installer.hooks_dir
        if hooks_dir.exists():
            import shutil
            shutil.rmtree(str(hooks_dir))
        installer.install()
        assert hooks_dir.exists()

    def test_install_already_installed_returns_failure(self, installer: HookInstaller) -> None:
        installer.install()
        result = installer.install()  # second install without force
        assert result.success is False

    def test_install_force_overwrites_own_hook(self, installer: HookInstaller) -> None:
        installer.install()
        result = installer.install(force=True)
        assert result.success is True

    def test_install_raises_on_foreign_hook_without_force(
        self, installer: HookInstaller
    ) -> None:
        installer.hooks_dir.mkdir(parents=True, exist_ok=True)
        installer.hook_path.write_text("#!/bin/bash\necho hello\n")
        with pytest.raises(ExistingHookError):
            installer.install(force=False)

    def test_install_force_overwrites_foreign_hook(self, installer: HookInstaller) -> None:
        installer.hooks_dir.mkdir(parents=True, exist_ok=True)
        installer.hook_path.write_text("#!/bin/bash\necho hello\n")
        result = installer.install(force=True)
        assert result.success is True
        assert _HOOK_MARKER in installer.hook_path.read_text()

    def test_install_backup_created_on_overwrite(self, installer: HookInstaller) -> None:
        installer.hooks_dir.mkdir(parents=True, exist_ok=True)
        installer.hook_path.write_text("#!/bin/bash\necho original\n")
        installer.install(force=True, backup=True)
        bak_path = installer.hook_path.with_suffix(".bak")
        assert bak_path.exists()
        assert "original" in bak_path.read_text()

    def test_install_no_backup_when_disabled(self, installer: HookInstaller) -> None:
        installer.hooks_dir.mkdir(parents=True, exist_ok=True)
        installer.hook_path.write_text("#!/bin/bash\necho original\n")
        installer.install(force=True, backup=False)
        bak_path = installer.hook_path.with_suffix(".bak")
        assert not bak_path.exists()

    def test_install_result_contains_hook_path(self, installer: HookInstaller) -> None:
        result = installer.install()
        assert result.hook_path == installer.hook_path

    def test_install_result_message_nonempty(self, installer: HookInstaller) -> None:
        result = installer.install()
        assert result.message.strip() != ""


# ---------------------------------------------------------------------------
# CI override mode
# ---------------------------------------------------------------------------


class TestCIOverrideMode:
    """Tests for CI override hook generation."""

    def test_ci_override_hook_installed(self, repo_path: Path) -> None:
        installer = HookInstaller(repo_path=repo_path, ci_override=True)
        result = installer.install()
        assert result.success is True

    def test_ci_override_hook_contains_ci_flag(self, repo_path: Path) -> None:
        installer = HookInstaller(repo_path=repo_path, ci_override=True)
        installer.install()
        content = installer.hook_path.read_text(encoding="utf-8")
        assert "--ci-override" in content

    def test_ci_override_hook_non_blocking(self, repo_path: Path) -> None:
        installer = HookInstaller(repo_path=repo_path, ci_override=True)
        installer.install()
        content = installer.hook_path.read_text(encoding="utf-8")
        # In CI override mode, the script should not exit 1 on findings
        # The template uses '|| true' to prevent failure propagation
        assert "non-blocking" in content or "|| true" in content

    def test_normal_hook_is_blocking(self, installer: HookInstaller) -> None:
        installer.install()
        content = installer.hook_path.read_text(encoding="utf-8")
        assert "exit 1" in content


# ---------------------------------------------------------------------------
# Min severity in hook script
# ---------------------------------------------------------------------------


class TestMinSeverityInHook:
    """Tests that min_severity is correctly embedded in the hook script."""

    def test_critical_severity_in_hook(self, repo_path: Path) -> None:
        installer = HookInstaller(repo_path=repo_path, min_severity="critical")
        installer.install()
        content = installer.hook_path.read_text(encoding="utf-8")
        assert "critical" in content

    def test_high_severity_in_hook(self, repo_path: Path) -> None:
        installer = HookInstaller(repo_path=repo_path, min_severity="high")
        installer.install()
        content = installer.hook_path.read_text(encoding="utf-8")
        assert "high" in content

    def test_version_in_hook(self, repo_path: Path) -> None:
        from contagious_scan import __version__
        installer = HookInstaller(repo_path=repo_path)
        installer.install()
        content = installer.hook_path.read_text(encoding="utf-8")
        assert __version__ in content


# ---------------------------------------------------------------------------
# uninstall() tests
# ---------------------------------------------------------------------------


class TestHookUninstall:
    """Tests for HookInstaller.uninstall."""

    def test_uninstall_removes_hook_file(self, installer: HookInstaller) -> None:
        installer.install()
        assert installer.hook_path.exists()
        installer.uninstall()
        assert not installer.hook_path.exists()

    def test_uninstall_returns_success(self, installer: HookInstaller) -> None:
        installer.install()
        result = installer.uninstall()
        assert result.success is True

    def test_uninstall_when_not_installed_returns_success(self, installer: HookInstaller) -> None:
        # No hook installed — should succeed gracefully
        result = installer.uninstall()
        assert result.success is True

    def test_uninstall_foreign_hook_returns_failure(self, installer: HookInstaller) -> None:
        installer.hooks_dir.mkdir(parents=True, exist_ok=True)
        installer.hook_path.write_text("#!/bin/bash\necho foreign\n")
        result = installer.uninstall()
        assert result.success is False
        # Foreign hook must NOT be removed
        assert installer.hook_path.exists()

    def test_uninstall_returns_install_result(self, installer: HookInstaller) -> None:
        installer.install()
        result = installer.uninstall()
        assert isinstance(result, InstallResult)

    def test_is_installed_false_after_uninstall(self, installer: HookInstaller) -> None:
        installer.install()
        installer.uninstall()
        assert installer.is_installed() is False


# ---------------------------------------------------------------------------
# status() tests
# ---------------------------------------------------------------------------


class TestHookStatus:
    """Tests for HookInstaller.status."""

    def test_status_returns_dict(self, installer: HookInstaller) -> None:
        status = installer.status()
        assert isinstance(status, dict)

    def test_status_keys(self, installer: HookInstaller) -> None:
        status = installer.status()
        expected_keys = {
            "installed", "hook_path", "hooks_dir_exists",
            "hook_file_exists", "hook_executable", "our_hook",
            "ci_override", "min_severity", "repo_path",
        }
        assert expected_keys.issubset(set(status.keys()))

    def test_status_not_installed_initially(self, installer: HookInstaller) -> None:
        status = installer.status()
        assert status["installed"] is False
        assert status["hook_file_exists"] is False

    def test_status_installed_after_install(self, installer: HookInstaller) -> None:
        installer.install()
        status = installer.status()
        assert status["installed"] is True
        assert status["hook_file_exists"] is True
        assert status["hook_executable"] is True
        assert status["our_hook"] is True

    def test_status_ci_override_reflected(self, repo_path: Path) -> None:
        installer = HookInstaller(repo_path=repo_path, ci_override=True)
        status = installer.status()
        assert status["ci_override"] is True

    def test_status_min_severity_reflected(self, repo_path: Path) -> None:
        installer = HookInstaller(repo_path=repo_path, min_severity="high")
        status = installer.status()
        assert status["min_severity"] == "high"


# ---------------------------------------------------------------------------
# get_hook_content() tests
# ---------------------------------------------------------------------------


class TestGetHookContent:
    """Tests for HookInstaller.get_hook_content."""

    def test_returns_none_when_no_hook(self, installer: HookInstaller) -> None:
        assert installer.get_hook_content() is None

    def test_returns_string_after_install(self, installer: HookInstaller) -> None:
        installer.install()
        content = installer.get_hook_content()
        assert isinstance(content, str)
        assert len(content) > 0

    def test_content_contains_marker(self, installer: HookInstaller) -> None:
        installer.install()
        content = installer.get_hook_content()
        assert content is not None
        assert _HOOK_MARKER in content


# ---------------------------------------------------------------------------
# Module-level convenience function tests
# ---------------------------------------------------------------------------


class TestConvenienceFunctions:
    """Tests for module-level install_hook, uninstall_hook, is_hook_installed."""

    def test_install_hook_function(self, repo_path: Path) -> None:
        result = install_hook(repo_path)
        assert result.success is True

    def test_is_hook_installed_true_after_install(self, repo_path: Path) -> None:
        install_hook(repo_path)
        assert is_hook_installed(repo_path) is True

    def test_is_hook_installed_false_before_install(self, repo_path: Path) -> None:
        assert is_hook_installed(repo_path) is False

    def test_uninstall_hook_function(self, repo_path: Path) -> None:
        install_hook(repo_path)
        result = uninstall_hook(repo_path)
        assert result.success is True
        assert not is_hook_installed(repo_path)

    def test_get_hook_status_function(self, repo_path: Path) -> None:
        status = get_hook_status(repo_path)
        assert isinstance(status, dict)
        assert "installed" in status

    def test_install_hook_ci_override(self, repo_path: Path) -> None:
        result = install_hook(repo_path, ci_override=True)
        assert result.success is True
        content = (Path(result.hook_path)).read_text()
        assert "--ci-override" in content

    def test_install_hook_not_git_repo_raises(self, tmp_path: Path) -> None:
        empty = tmp_path / "not_a_repo"
        empty.mkdir()
        with pytest.raises(NotAGitRepoError):
            install_hook(empty)

    def test_uninstall_hook_not_git_repo_raises(self, tmp_path: Path) -> None:
        empty = tmp_path / "not_a_repo"
        empty.mkdir()
        with pytest.raises(NotAGitRepoError):
            uninstall_hook(empty)

    def test_install_hook_with_min_severity(self, repo_path: Path) -> None:
        result = install_hook(repo_path, min_severity="high")
        content = Path(result.hook_path).read_text()
        assert "high" in content

    def test_install_hook_force(self, repo_path: Path) -> None:
        install_hook(repo_path)
        # Second install with force=True should succeed
        result = install_hook(repo_path, force=True)
        assert result.success is True
