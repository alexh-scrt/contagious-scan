"""Smoke tests for the contagious_scan package initialisation.

Verifies that the package is importable, exposes the expected public symbols,
and that the version string is well-formed.
"""

from __future__ import annotations

import re

import contagious_scan


def test_version_is_defined() -> None:
    """__version__ must be a non-empty string."""
    assert hasattr(contagious_scan, "__version__")
    assert isinstance(contagious_scan.__version__, str)
    assert contagious_scan.__version__ != ""


def test_version_format() -> None:
    """Version string must follow semver-like MAJOR.MINOR.PATCH format."""
    pattern = re.compile(r"^\d+\.\d+\.\d+")
    assert pattern.match(contagious_scan.__version__), (
        f"Version '{contagious_scan.__version__}' does not match expected format."
    )


def test_author_is_defined() -> None:
    """__author__ must be a non-empty string."""
    assert hasattr(contagious_scan, "__author__")
    assert isinstance(contagious_scan.__author__, str)
    assert contagious_scan.__author__ != ""


def test_license_is_defined() -> None:
    """__license__ must be exposed."""
    assert hasattr(contagious_scan, "__license__")
    assert contagious_scan.__license__ == "MIT"


def test_all_exports() -> None:
    """All symbols listed in __all__ must be importable from the package."""
    for name in contagious_scan.__all__:
        assert hasattr(contagious_scan, name), (
            f"Symbol '{name}' listed in __all__ but not found on the package."
        )
