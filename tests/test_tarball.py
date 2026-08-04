"""Extraction of untrusted npm tarballs must stay inside the target directory."""

import io
import tarfile

import pytest

from korvyr.scanner.tarball import UnsafeTarballError, extract_package, tarball_url


def _write_tar(path, members):
    with tarfile.open(path, "w:gz") as tar:
        for name, payload in members:
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            tar.addfile(info, io.BytesIO(payload))


def test_tarball_url_unscoped():
    url = tarball_url("https://registry.npmjs.org", "is-number", "7.0.0")
    assert url == "https://registry.npmjs.org/is-number/-/is-number-7.0.0.tgz"


def test_tarball_url_scoped_encodes_scope():
    url = tarball_url("https://registry.npmjs.org/", "@babel/core", "7.24.0")
    assert url == "https://registry.npmjs.org/@babel%2fcore/-/core-7.24.0.tgz"


def test_extract_package_returns_package_root(tmp_path):
    archive = tmp_path / "pkg.tgz"
    _write_tar(archive, [("package/package.json", b'{"name":"demo"}')])

    package_dir = extract_package(archive, tmp_path / "out")

    assert package_dir.name == "package"
    assert (package_dir / "package.json").exists()


def test_extract_package_without_package_prefix(tmp_path):
    archive = tmp_path / "flat.tgz"
    _write_tar(archive, [("index.js", b"module.exports = 1;")])

    package_dir = extract_package(archive, tmp_path / "out")

    assert (package_dir / "index.js").exists()


def test_extract_package_rejects_path_traversal(tmp_path):
    archive = tmp_path / "evil.tgz"
    _write_tar(archive, [("../escaped.js", b"pwned")])

    with pytest.raises(UnsafeTarballError):
        extract_package(archive, tmp_path / "out")

    assert not (tmp_path / "escaped.js").exists()


def test_extract_package_skips_symlinks(tmp_path):
    archive = tmp_path / "link.tgz"
    with tarfile.open(archive, "w:gz") as tar:
        link = tarfile.TarInfo("package/evil-link")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/passwd"
        tar.addfile(link)
        payload = b'{"name":"demo"}'
        info = tarfile.TarInfo("package/package.json")
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))

    package_dir = extract_package(archive, tmp_path / "out")

    assert (package_dir / "package.json").exists()
    assert not (package_dir / "evil-link").exists()
