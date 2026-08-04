"""Fetching and safely unpacking npm package tarballs.

Korvyr routinely extracts tarballs that are *expected* to be malicious, so
extraction must never write outside the destination directory. Every code path
that unpacks a package goes through :func:`extract_package`.
"""

from __future__ import annotations

import logging
import tarfile
from pathlib import Path

log = logging.getLogger(__name__)


class UnsafeTarballError(ValueError):
    """Raised when an archive member would escape the extraction directory."""


def tarball_url(registry: str, name: str, version: str) -> str:
    """Return the registry download URL for ``name@version``.

    Scoped packages live at ``/@scope%2fname/-/name-version.tgz``, which is why
    the scope is percent-encoded in the path segment but stripped from the
    filename.
    """
    if name.startswith("@"):
        scope, _, unscoped = name.partition("/")
        path_name = f"{scope}%2f{unscoped}"
    else:
        path_name = name
        unscoped = name
    return f"{registry.rstrip('/')}/{path_name}/-/{unscoped}-{version}.tgz"


def _is_within(base: Path, target: Path) -> bool:
    try:
        target.resolve().relative_to(base.resolve())
    except ValueError:
        return False
    return True


def _safe_members(archive: tarfile.TarFile, dest: Path):
    for member in archive.getmembers():
        if member.islnk() or member.issym():
            log.debug("Skipping link member %s", member.name)
            continue
        if not (member.isfile() or member.isdir()):
            log.debug("Skipping special member %s", member.name)
            continue
        member_path = dest / member.name
        if not _is_within(dest, member_path):
            raise UnsafeTarballError(
                f"Archive member '{member.name}' escapes the extraction directory"
            )
        yield member


def extract_package(tar_path: str | Path, dest_dir: str | Path) -> Path:
    """Extract an npm tarball into *dest_dir* and return the package root.

    npm tarballs wrap their contents in a top-level ``package/`` directory; if
    that directory is absent the extraction root itself is returned.
    """
    dest = Path(dest_dir)
    dest.mkdir(parents=True, exist_ok=True)
    with tarfile.open(tar_path, "r:*") as archive:
        members = list(_safe_members(archive, dest))
        if hasattr(tarfile, "data_filter"):
            archive.extractall(dest, members=members, filter="data")
        else:  # pragma: no cover - Python < 3.12
            archive.extractall(dest, members=members)

    package_dir = dest / "package"
    return package_dir if package_dir.is_dir() else dest
