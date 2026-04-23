"""Git utility helpers for contagious_scan.

Provides functions to:
- Enumerate staged files in a Git repository (for pre-push hook mode)
- Walk repository commit history to find files across commits
- Clone remote URLs to a temporary directory for scanning
- Enumerate all tracked files in the working tree

All functions use GitPython (``git`` package) and fall back to subprocess
when necessary for operations not exposed by GitPython's high-level API.

Typical usage::

    from contagious_scan.git_utils import (
        get_staged_files,
        get_repo_files,
        clone_remote_repo,
        is_git_repo,
    )
"""

from __future__ import annotations

import logging
import shutil
import tempfile
from pathlib import Path
from typing import Generator, Iterator

try:
    import git
    from git import InvalidGitRepositoryError, NoSuchPathError, Repo
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "GitPython is required. Install it with: pip install gitpython"
    ) from exc

logger = logging.getLogger(__name__)

# File extensions considered scannable text files
_TEXT_EXTENSIONS: frozenset[str] = frozenset({
    ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx",
    ".py", ".pyw",
    ".sh", ".bash", ".zsh", ".ksh", ".fish",
    ".json",
    ".yml", ".yaml",
    ".toml",
    ".cfg",
    ".ini",
    ".env",
    ".rb",
    ".go",
    ".rs",
    ".java",
    ".kt",
    ".gradle",
    ".xml",
    ".html", ".htm",
    ".md",
    ".txt",
    ".lock",
    ".tf",
    ".hcl",
    ".dockerfile",
    "",  # files with no extension (e.g. Makefile, Dockerfile)
})

# Maximum file size to read (10 MB) to avoid memory issues with large binaries
_MAX_FILE_SIZE_BYTES: int = 10 * 1024 * 1024


class GitUtilsError(Exception):
    """Base exception for git_utils errors."""


class NotAGitRepoError(GitUtilsError):
    """Raised when the target path is not a Git repository."""


class CloneError(GitUtilsError):
    """Raised when cloning a remote repository fails."""


def is_git_repo(path: str | Path) -> bool:
    """Return ``True`` if *path* is inside a valid Git repository.

    Parameters
    ----------
    path:
        Directory path to check.

    Returns
    -------
    bool
        ``True`` if path is a Git repository root or subdirectory.
    """
    try:
        Repo(str(path), search_parent_directories=True)
        return True
    except (InvalidGitRepositoryError, NoSuchPathError):
        return False


def _open_repo(path: str | Path) -> Repo:
    """Open a Git repository at *path*, searching parent directories.

    Parameters
    ----------
    path:
        Path to the repository root or a subdirectory.

    Returns
    -------
    git.Repo
        Opened repository object.

    Raises
    ------
    NotAGitRepoError
        If *path* is not within a Git repository.
    """
    try:
        return Repo(str(path), search_parent_directories=True)
    except (InvalidGitRepositoryError, NoSuchPathError) as exc:
        raise NotAGitRepoError(
            f"'{path}' is not a valid Git repository: {exc}"
        ) from exc


def get_staged_files(repo_path: str | Path) -> list[Path]:
    """Return a list of files currently staged in the Git index.

    Only returns files that exist on disk (not deleted staged files) and
    that have scannable extensions.

    Parameters
    ----------
    repo_path:
        Path to the repository root or any subdirectory.

    Returns
    -------
    list[Path]
        Absolute paths of staged scannable files.

    Raises
    ------
    NotAGitRepoError
        If *repo_path* is not within a Git repository.
    """
    repo = _open_repo(repo_path)
    repo_root = Path(repo.working_tree_dir)  # type: ignore[arg-type]

    staged_paths: list[Path] = []

    try:
        # Get all staged items from the index
        for item in repo.index.diff("HEAD"):
            file_path = repo_root / item.a_path
            if _is_scannable(file_path):
                staged_paths.append(file_path)
    except git.exc.BadName:
        # Repository has no commits yet — use index directly
        for entry in repo.index.entries.values():
            file_path = repo_root / entry.path
            if _is_scannable(file_path):
                staged_paths.append(file_path)

    # Also include new files added to index (untracked but staged)
    try:
        for item in repo.index.diff(None):
            # diff(None) gives working tree vs index; we want index vs HEAD
            pass
    except Exception:  # noqa: BLE001
        pass

    # Use git status to capture all staged files more reliably
    try:
        staged_paths = _get_staged_via_status(repo, repo_root)
    except Exception as exc:  # noqa: BLE001
        logger.debug("Falling back to index diff for staged files: %s", exc)

    return staged_paths


def _get_staged_via_status(repo: Repo, repo_root: Path) -> list[Path]:
    """Use ``git status --porcelain`` to enumerate staged files.

    This is more reliable than the GitPython index API for capturing
    all staged changes including new files.

    Parameters
    ----------
    repo:
        Open GitPython Repo object.
    repo_root:
        Absolute path to the repository root.

    Returns
    -------
    list[Path]
        Absolute paths of staged scannable files.
    """
    staged: list[Path] = []
    # Index status codes where the file is staged: A, M, R, C, T
    staged_codes = {"A", "M", "R", "C", "T"}

    output: str = repo.git.status("--porcelain", "-z")
    if not output:
        return staged

    # Records are NUL-separated in -z mode
    records = output.split("\x00")
    for record in records:
        if len(record) < 4:
            continue
        index_status = record[0]  # first char is index status
        # working_status = record[1]  # second char is working tree status
        filepath = record[3:].strip()  # filename starts at position 3
        if index_status in staged_codes and filepath:
            abs_path = repo_root / filepath
            if _is_scannable(abs_path):
                staged.append(abs_path)

    return staged


def get_repo_files(
    repo_path: str | Path,
    include_untracked: bool = False,
) -> list[Path]:
    """Return all scannable files in a repository's working tree.

    Parameters
    ----------
    repo_path:
        Path to the repository root.
    include_untracked:
        If ``True``, also include untracked (new) files not yet committed.
        Defaults to ``False``.

    Returns
    -------
    list[Path]
        Absolute paths of scannable files in the working tree.

    Raises
    ------
    NotAGitRepoError
        If *repo_path* is not a valid Git repository.
    """
    repo = _open_repo(repo_path)
    repo_root = Path(repo.working_tree_dir)  # type: ignore[arg-type]

    tracked: list[Path] = []

    # Get all tracked files via the index
    for entry in repo.index.entries.values():
        abs_path = repo_root / entry.path
        if _is_scannable(abs_path):
            tracked.append(abs_path)

    if include_untracked:
        try:
            untracked = repo.untracked_files
            for rel_path in untracked:
                abs_path = repo_root / rel_path
                if _is_scannable(abs_path):
                    tracked.append(abs_path)
        except Exception as exc:  # noqa: BLE001
            logger.debug("Could not enumerate untracked files: %s", exc)

    # Deduplicate while preserving order
    seen: set[Path] = set()
    unique: list[Path] = []
    for p in tracked:
        if p not in seen:
            seen.add(p)
            unique.append(p)

    return unique


def walk_repo_files(
    repo_path: str | Path,
    include_untracked: bool = False,
) -> Iterator[Path]:
    """Yield scannable file paths from the repository working tree.

    This is a generator variant of :func:`get_repo_files` suitable for
    large repositories where memory efficiency matters.

    Parameters
    ----------
    repo_path:
        Path to the repository root.
    include_untracked:
        If ``True``, also yield untracked files.

    Yields
    ------
    Path
        Absolute path of each scannable file.

    Raises
    ------
    NotAGitRepoError
        If *repo_path* is not a valid Git repository.
    """
    for path in get_repo_files(repo_path, include_untracked=include_untracked):
        yield path


def get_files_from_directory(
    directory: str | Path,
    recursive: bool = True,
) -> list[Path]:
    """Return all scannable files under *directory* without requiring a Git repo.

    This function is used when scanning a directory that is not a Git
    repository (e.g. an extracted tarball or cloned repo).

    Parameters
    ----------
    directory:
        Root directory to walk.
    recursive:
        If ``True`` (default), recursively scan all subdirectories.

    Returns
    -------
    list[Path]
        Scannable file paths under *directory*.
    """
    root = Path(directory)
    if not root.is_dir():
        raise ValueError(f"'{directory}' is not a directory")

    files: list[Path] = []
    pattern = "**/*" if recursive else "*"

    for path in root.glob(pattern):
        if path.is_file() and _is_scannable(path):
            files.append(path)

    return sorted(files)


def get_commit_history_files(
    repo_path: str | Path,
    max_commits: int = 50,
    branch: str | None = None,
) -> list[tuple[str, str, bytes]]:
    """Walk commit history and return file contents from each commit.

    Returns a list of ``(commit_sha, relative_path, content_bytes)`` tuples
    for all scannable files modified in the last *max_commits* commits.

    Parameters
    ----------
    repo_path:
        Path to the repository root.
    max_commits:
        Maximum number of commits to inspect. Defaults to 50.
    branch:
        Branch name to walk. Defaults to the current active branch.

    Returns
    -------
    list[tuple[str, str, bytes]]
        Tuples of ``(commit_sha, file_path, content_bytes)``.

    Raises
    ------
    NotAGitRepoError
        If *repo_path* is not a valid Git repository.
    """
    repo = _open_repo(repo_path)
    results: list[tuple[str, str, bytes]] = []
    seen_blobs: set[str] = set()  # avoid re-scanning identical blobs

    try:
        rev = branch if branch else repo.active_branch.name
        commits = list(repo.iter_commits(rev, max_count=max_commits))
    except Exception as exc:  # noqa: BLE001
        logger.debug("Could not iterate commits: %s", exc)
        return results

    for commit in commits:
        try:
            for item in commit.tree.traverse():
                if item.type != "blob":  # type: ignore[union-attr]
                    continue
                blob = item  # type: ignore[assignment]
                if blob.hexsha in seen_blobs:
                    continue
                rel_path = blob.path
                if not _is_scannable_path(rel_path):
                    continue
                if blob.size > _MAX_FILE_SIZE_BYTES:
                    logger.debug(
                        "Skipping large blob %s (%d bytes)", rel_path, blob.size
                    )
                    continue
                try:
                    content = blob.data_stream.read()
                    results.append((commit.hexsha, rel_path, content))
                    seen_blobs.add(blob.hexsha)
                except Exception as exc:  # noqa: BLE001
                    logger.debug(
                        "Could not read blob %s in commit %s: %s",
                        rel_path, commit.hexsha, exc,
                    )
        except Exception as exc:  # noqa: BLE001
            logger.debug("Error traversing commit %s: %s", commit.hexsha, exc)

    return results


def clone_remote_repo(
    url: str,
    target_dir: str | Path | None = None,
    depth: int | None = 1,
    branch: str | None = None,
) -> Path:
    """Clone a remote Git repository to a local directory.

    Parameters
    ----------
    url:
        Remote repository URL (HTTPS or SSH).
    target_dir:
        Local directory to clone into. If ``None``, a temporary directory
        is created automatically. The caller is responsible for cleanup
        when a custom *target_dir* is provided.
    depth:
        Shallow clone depth.  Set to ``None`` for a full clone.
        Defaults to ``1`` (shallow) for faster scanning.
    branch:
        Branch to clone. Defaults to the remote's default branch.

    Returns
    -------
    Path
        Path to the cloned repository root.

    Raises
    ------
    CloneError
        If the clone operation fails.
    """
    if target_dir is None:
        target_dir = Path(tempfile.mkdtemp(prefix="contagious_scan_clone_"))
    else:
        target_dir = Path(target_dir)
        target_dir.mkdir(parents=True, exist_ok=True)

    clone_kwargs: dict[str, object] = {}
    if depth is not None:
        clone_kwargs["depth"] = depth
    if branch is not None:
        clone_kwargs["branch"] = branch

    logger.info("Cloning %s -> %s", url, target_dir)
    try:
        Repo.clone_from(url, str(target_dir), **clone_kwargs)  # type: ignore[arg-type]
    except git.exc.GitCommandError as exc:
        # Clean up partial clone on failure
        try:
            shutil.rmtree(str(target_dir), ignore_errors=True)
        except Exception:  # noqa: BLE001
            pass
        raise CloneError(f"Failed to clone '{url}': {exc}") from exc
    except Exception as exc:  # noqa: BLE001
        try:
            shutil.rmtree(str(target_dir), ignore_errors=True)
        except Exception:  # noqa: BLE001
            pass
        raise CloneError(f"Unexpected error cloning '{url}': {exc}") from exc

    return target_dir


def get_repo_root(path: str | Path) -> Path:
    """Return the root directory of the Git repository containing *path*.

    Parameters
    ----------
    path:
        A path inside a Git repository.

    Returns
    -------
    Path
        Absolute path to the repository root.

    Raises
    ------
    NotAGitRepoError
        If *path* is not within a Git repository.
    """
    repo = _open_repo(path)
    return Path(repo.working_tree_dir)  # type: ignore[arg-type]


def get_current_branch(repo_path: str | Path) -> str | None:
    """Return the name of the current active branch.

    Parameters
    ----------
    repo_path:
        Path to the repository root.

    Returns
    -------
    str or None
        Branch name, or ``None`` if in detached HEAD state.

    Raises
    ------
    NotAGitRepoError
        If *repo_path* is not a valid Git repository.
    """
    repo = _open_repo(repo_path)
    try:
        return repo.active_branch.name
    except TypeError:
        # Detached HEAD state
        return None


def read_file_content(
    path: Path,
    encoding: str = "utf-8",
) -> tuple[str, bytes]:
    """Read a file and return both decoded text and raw bytes.

    Attempts UTF-8 decoding first, then falls back to latin-1 which
    never raises a ``UnicodeDecodeError``.

    Parameters
    ----------
    path:
        Path to the file to read.
    encoding:
        Preferred encoding. Defaults to ``"utf-8"``.

    Returns
    -------
    tuple[str, bytes]
        A ``(text_content, raw_bytes)`` pair.

    Raises
    ------
    OSError
        If the file cannot be read.
    ValueError
        If the file exceeds the maximum size limit.
    """
    stat = path.stat()
    if stat.st_size > _MAX_FILE_SIZE_BYTES:
        raise ValueError(
            f"File '{path}' is too large to scan "
            f"({stat.st_size} bytes > {_MAX_FILE_SIZE_BYTES} bytes)"
        )

    raw = path.read_bytes()
    try:
        text = raw.decode(encoding)
    except UnicodeDecodeError:
        try:
            text = raw.decode("latin-1")
        except UnicodeDecodeError:
            text = raw.decode("utf-8", errors="replace")

    return text, raw


def _is_scannable(path: Path) -> bool:
    """Return ``True`` if *path* is a file with a scannable extension.

    Parameters
    ----------
    path:
        File path to check.

    Returns
    -------
    bool
        ``True`` if the file exists, is a regular file, is not too large,
        and has a recognised scannable extension.
    """
    if not path.exists() or not path.is_file():
        return False
    return _is_scannable_path(str(path))


def _is_scannable_path(rel_path: str) -> bool:
    """Return ``True`` if *rel_path* has a scannable extension.

    Parameters
    ----------
    rel_path:
        Relative file path string.

    Returns
    -------
    bool
        ``True`` if the file extension is in the scannable set.
    """
    ext = Path(rel_path).suffix.lower()
    name = Path(rel_path).name.lower()

    # Always scan these known important filenames regardless of extension
    _important_names = {
        "dockerfile", "makefile", "jenkinsfile", "procfile",
        ".env", ".envrc", "brewfile", "gemfile", "podfile",
    }
    if name in _important_names:
        return True

    # Skip obviously binary extensions
    _binary_extensions = {
        ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg",
        ".mp3", ".mp4", ".wav", ".avi", ".mov",
        ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar",
        ".exe", ".dll", ".so", ".dylib", ".a", ".o",
        ".pyc", ".pyo", ".class",
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".db", ".sqlite", ".sqlite3",
        ".woff", ".woff2", ".ttf", ".eot", ".otf",
        ".bin", ".dat", ".img",
    }
    if ext in _binary_extensions:
        return False

    return ext in _TEXT_EXTENSIONS
