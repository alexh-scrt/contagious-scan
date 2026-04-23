"""contagious_scan - Security CLI tool for auditing Git repositories.

Detects indicators of DPRK-style 'Contagious Interview' supply chain attacks
including BeaverTail and InvisibleFerret RAT payloads, obfuscated loaders,
suspicious lifecycle hooks, and tampered dependency manifests.

Typical usage::

    from contagious_scan import __version__
    from contagious_scan.scanner import Scanner
    from contagious_scan.reporter import Reporter
"""

from __future__ import annotations

__version__ = "0.1.0"
__author__ = "contagious_scan contributors"
__license__ = "MIT"

__all__ = ["__version__", "__author__", "__license__"]
