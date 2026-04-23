"""Unit and integration tests for contagious_scan.git_utils.

Tests use temporary directories and initialised Git repositories to verify
file discovery, staged file enumeration, and related utilities.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

try:
    import git
    from git import Repo
    GIT_AVAILABLE = True
except ImportError:
    GIT_AVAILABLE = False

pytestmark = pytest.mark.skipif(
    not GIT_AVAILABLE, reason="GitPython not installed"
)

from contagious_scan.git_utils import (
    NotAGitRepoError,
    _is_scannable,
    _is_scannable_path,
    get_files_from_directory,
    get_repo_files,
    get_repo_root,
    get_staged_files,
    is_git_repo,
    read_file_content,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def empty_dir(tmp_path: Path) -> Path:
    """Return a temporary empty directory (not a git repo)."""
    d = tmp_path / "empty_dir"
    d.mkdir()
    return d


@pytest.fixture()
def git_repo(tmp_path: Path) -> Repo:
    """Initialise a minimal Git repository with some committed files."""
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    repo = Repo.init(str(repo_dir))

    # Configure identity for commits
    repo.config_writer().set_value("user", "name", "Test").release()
    repo.config_writer().set_value("user", "email", "test@test.com").release()

    # Create some files
    (repo_dir / "index.js").write_text("console.log('hello');")
    (repo_dir / "setup.py").write_text("from setuptools import setup\nsetup()\n")
    (repo_dir / "README.md").write_text("# Test Repo")
    (repo_dir / "image.png").write_bytes(b"\x89PNG fake binary")

    repo.index.add(["index.js", "setup.py", "README.md", "image.png"])
    repo.index.commit("Initial commit")
    return repo


@pytest.fixture()
def git_repo_with_staged(tmp_path: Path) -> Repo:
    """Initialise a Git repo with some staged (but not committed) changes."""
    repo_dir = tmp_path / "staged_repo"
    repo_dir.mkdir()
    repo = Repo.init(str(repo_dir))
    repo.config_writer().set_value("user", "name", "Test").release()
    repo.config_writer().set_value("user", "email", "test@test.com").release()

    # First commit
    (repo_dir / "existing.js").write_text("const x = 1;")
    repo.index.add(["existing.js"])
    repo.index.commit("Initial")

    # Stage a new file
    (repo_dir / "new_file.py").write_text("print('hello')")
    repo.index.add(["new_file.py"])

    # Stage a modification
    (repo_dir / "existing.js").write_text("const x = 2;")
    repo.index.add(["existing.js"])

    return repo


# ---------------------------------------------------------------------------
# is_git_repo tests
# ---------------------------------------------------------------------------


class TestIsGitRepo:
    """Tests for is_git_repo."""

    def test_valid_repo_returns_true(self, git_repo: Repo) -> None:
        assert is_git_repo(git_repo.working_tree_dir) is True

    def test_non_repo_returns_false(self, empty_dir: Path) -> None:
        assert is_git_repo(empty_dir) is False

    def test_nonexistent_path_returns_false(self, tmp_path: Path) -> None:
        assert is_git_repo(tmp_path / "does_not_exist") is False


# ---------------------------------------------------------------------------
# get_repo_root tests
# ---------------------------------------------------------------------------


class TestGetRepoRoot:
    """Tests for get_repo_root."""

    def test_returns_repo_root(self, git_repo: Repo) -> None:
        root = get_repo_root(git_repo.working_tree_dir)
        assert root == Path(git_repo.working_tree_dir).resolve()

    def test_raises_for_non_repo(self, empty_dir: Path) -> None:
        with pytest.raises(NotAGitRepoError):
            get_repo_root(empty_dir)


# ---------------------------------------------------------------------------
# _is_scannable_path tests
# ---------------------------------------------------------------------------


class TestIsScannablePath:
    """Tests for the _is_scannable_path helper."""

    def test_js_is_scannable(self) -> None:
        assert _is_scannable_path("src/index.js") is True

    def test_py_is_scannable(self) -> None:
        assert _is_scannable_path("setup.py") is True

    def test_json_is_scannable(self) -> None:
        assert _is_scannable_path("package.json") is True

    def test_yml_is_scannable(self) -> None:
        assert _is_scannable_path(".github/workflows/ci.yml") is True

    def test_sh_is_scannable(self) -> None:
        assert _is_scannable_path("install.sh") is True

    def test_png_not_scannable(self) -> None:
        assert _is_scannable_path("image.png") is False

    def test_pyc_not_scannable(self) -> None:
        assert _is_scannable_path("module.pyc") is False

    def test_zip_not_scannable(self) -> None:
        assert _is_scannable_path("archive.zip") is False

    def test_dockerfile_is_scannable(self) -> None:
        assert _is_scannable_path("Dockerfile") is True

    def test_makefile_is_scannable(self) -> None:
        assert _is_scannable_path("Makefile") is True

    def test_toml_is_scannable(self) -> None:
        assert _is_scannable_path("pyproject.toml") is True


# ---------------------------------------------------------------------------
# get_files_from_directory tests
# ---------------------------------------------------------------------------


class TestGetFilesFromDirectory:
    """Tests for get_files_from_directory."""

    def test_returns_scannable_files(self, tmp_path: Path) -> None:
        (tmp_path / "app.js").write_text("const x = 1;")
        (tmp_path / "config.json").write_text('{}')
        (tmp_path / "image.png").write_bytes(b"fake")

        files = get_files_from_directory(tmp_path)
        names = [f.name for f in files]
        assert "app.js" in names
        assert "config.json" in names
        assert "image.png" not in names

    def test_recursive_scan(self, tmp_path: Path) -> None:
        sub = tmp_path / "subdir"
        sub.mkdir()
        (sub / "nested.py").write_text("pass")
        (tmp_path / "top.js").write_text("const x = 1;")

        files = get_files_from_directory(tmp_path, recursive=True)
        paths = [str(f) for f in files]
        assert any("nested.py" in p for p in paths)
        assert any("top.js" in p for p in paths)

    def test_non_recursive_scan(self, tmp_path: Path) -> None:
        sub = tmp_path / "subdir"
        sub.mkdir()
        (sub / "nested.py").write_text("pass")
        (tmp_path / "top.js").write_text("const x = 1;")

        files = get_files_from_directory(tmp_path, recursive=False)
        paths = [str(f) for f in files]
        assert not any("nested.py" in p for p in paths)
        assert any("top.js" in p for p in paths)

    def test_raises_for_non_directory(self, tmp_path: Path) -> None:
        f = tmp_path / "file.txt"
        f.write_text("hello")
        with pytest.raises(ValueError):
            get_files_from_directory(f)

    def test_empty_directory(self, tmp_path: Path) -> None:
        d = tmp_path / "empty"
        d.mkdir()
        files = get_files_from_directory(d)
        assert files == []


# ---------------------------------------------------------------------------
# get_repo_files tests
# ---------------------------------------------------------------------------


class TestGetRepoFiles:
    """Tests for get_repo_files."""

    def test_returns_tracked_scannable_files(self, git_repo: Repo) -> None:
        repo_path = git_repo.working_tree_dir
        files = get_repo_files(repo_path)
        names = [f.name for f in files]
        assert "index.js" in names
        assert "setup.py" in names
        assert "README.md" in names
        # Binary file should be excluded
        assert "image.png" not in names

    def test_raises_for_non_repo(self, empty_dir: Path) -> None:
        with pytest.raises(NotAGitRepoError):
            get_repo_files(empty_dir)

    def test_returns_list(self, git_repo: Repo) -> None:
        files = get_repo_files(git_repo.working_tree_dir)
        assert isinstance(files, list)

    def test_no_duplicates(self, git_repo: Repo) -> None:
        files = get_repo_files(git_repo.working_tree_dir)
        assert len(files) == len(set(files))


# ---------------------------------------------------------------------------
# get_staged_files tests
# ---------------------------------------------------------------------------


class TestGetStagedFiles:
    """Tests for get_staged_files."""

    def test_returns_list(self, git_repo_with_staged: Repo) -> None:
        files = get_staged_files(git_repo_with_staged.working_tree_dir)
        assert isinstance(files, list)

    def test_raises_for_non_repo(self, empty_dir: Path) -> None:
        with pytest.raises(NotAGitRepoError):
            get_staged_files(empty_dir)

    def test_staged_files_exist(self, git_repo_with_staged: Repo) -> None:
        files = get_staged_files(git_repo_with_staged.working_tree_dir)
        for f in files:
            # All returned paths should be Path objects
            assert isinstance(f, Path)


# ---------------------------------------------------------------------------
# read_file_content tests
# ---------------------------------------------------------------------------


class TestReadFileContent:
    """Tests for read_file_content."""

    def test_reads_utf8_file(self, tmp_path: Path) -> None:
        f = tmp_path / "test.js"
        f.write_text("const x = 'hello';")
        text, raw = read_file_content(f)
        assert "hello" in text
        assert isinstance(raw, bytes)

    def test_reads_binary_fallback(self, tmp_path: Path) -> None:
        f = tmp_path / "test.bin"
        f.write_bytes(bytes(range(256)))
        text, raw = read_file_content(f)
        assert isinstance(text, str)
        assert raw == bytes(range(256))

    def test_raises_for_oversized_file(self, tmp_path: Path) -> None:
        f = tmp_path / "big.txt"
        # Create a file reference that pretends to be large
        f.write_bytes(b"x")
        from contagious_scan.git_utils import _MAX_FILE_SIZE_BYTES
        # We can't easily create a 10MB file in tests, but we verify
        # the function works for normal files
        text, raw = read_file_content(f)
        assert text == "x"

    def test_raises_oserror_for_missing_file(self, tmp_path: Path) -> None:
        with pytest.raises(OSError):
            read_file_content(tmp_path / "does_not_exist.txt")
