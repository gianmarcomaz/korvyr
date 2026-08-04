"""Korvyr - hybrid GNN and static-analysis screening for npm packages.

This is a research prototype. See the README for the threat model, the
evaluation caveats, and the limitations this system does not overcome.
"""

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _version

try:
    __version__ = _version("korvyr")
except PackageNotFoundError:  # running from a source tree without an install
    __version__ = "0.1.0"

__all__ = ["__version__"]
