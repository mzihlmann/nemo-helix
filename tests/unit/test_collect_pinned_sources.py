# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import hashlib
import json
import sys
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "docker" / "scripts" / "collect-pinned-sources.py"
ARCHIVE = b"busybox source"


def load_module():
    spec = spec_from_file_location("collect_pinned_sources", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def write_manifest(path: Path, *, sha256: str = hashlib.sha256(ARCHIVE).hexdigest(), url: str | None = None) -> Path:
    path.write_text(
        json.dumps(
            {
                "sources": [
                    {
                        "name": "busybox",
                        "version": "1.38.0",
                        "license": "GPL-2.0-only",
                        "url": url or "https://busybox.net/downloads/busybox-1.38.0.tar.bz2",
                        "sha256": sha256,
                        "covers": ["binary:busybox@1.38.0"],
                    }
                ]
            }
        )
    )
    return path


class Response:
    def __init__(self, body: bytes) -> None:
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self) -> bytes:
        return self.body


def run(module, monkeypatch: pytest.MonkeyPatch, manifest: Path, output: Path) -> int:
    monkeypatch.setattr(sys, "argv", [str(SCRIPT), "--manifest", str(manifest), "--output", str(output)])
    return module.main()


def test_downloads_verified_archive_and_records_what_it_covers(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    module = load_module()
    monkeypatch.setenv("NHX_COLLECT_SOURCES", "1")
    monkeypatch.setattr(module.urllib.request, "urlopen", lambda url, timeout: Response(ARCHIVE))
    output = tmp_path / "out"

    assert run(module, monkeypatch, write_manifest(tmp_path / "m.json"), output) == 0

    assert (output / "pinned" / "busybox-1.38.0.tar.bz2").read_bytes() == ARCHIVE
    assert (output / "manifests" / "downloaded-pinned-sources.txt").read_text() == (
        "busybox==1.38.0\tbusybox-1.38.0.tar.bz2\thttps://busybox.net/downloads/busybox-1.38.0.tar.bz2"
        "\tGPL-2.0-only\tbinary:busybox@1.38.0\n"
    )


def test_checksum_mismatch_fails_without_writing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    module = load_module()
    monkeypatch.setenv("NHX_COLLECT_SOURCES", "1")
    monkeypatch.setattr(module.urllib.request, "urlopen", lambda url, timeout: Response(b"tampered"))
    output = tmp_path / "out"

    with pytest.raises(RuntimeError, match="sha256 mismatch"):
        run(module, monkeypatch, write_manifest(tmp_path / "m.json"), output)

    assert not (output / "pinned" / "busybox-1.38.0.tar.bz2").exists()


def test_download_failure_fails_the_build(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    module = load_module()
    monkeypatch.setenv("NHX_COLLECT_SOURCES", "1")
    monkeypatch.setattr(module, "sleep", lambda seconds: None)

    def unreachable(url: str, timeout: int) -> Response:
        raise module.urllib.error.URLError("TLS connect error")

    monkeypatch.setattr(module.urllib.request, "urlopen", unreachable)

    with pytest.raises(RuntimeError, match="could not download busybox 1.38.0"):
        run(module, monkeypatch, write_manifest(tmp_path / "m.json"), tmp_path / "out")


def test_disabled_collection_downloads_nothing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    module = load_module()
    monkeypatch.delenv("NHX_COLLECT_SOURCES", raising=False)
    monkeypatch.setattr(module.urllib.request, "urlopen", lambda url, timeout: pytest.fail("downloaded"))
    output = tmp_path / "out"

    assert run(module, monkeypatch, write_manifest(tmp_path / "m.json"), output) == 0

    assert (output / "manifests" / "source-collection-disabled.txt").exists()
    assert not (output / "pinned").exists()


@pytest.mark.parametrize(
    ("sha256", "url", "error"),
    [
        ("not-a-digest", None, "invalid sha256"),
        (hashlib.sha256(ARCHIVE).hexdigest(), "http://busybox.net/downloads/busybox-1.38.0.tar.bz2", "https"),
    ],
)
def test_manifest_is_validated_even_when_collection_is_disabled(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, sha256: str, url: str | None, error: str
) -> None:
    module = load_module()
    monkeypatch.delenv("NHX_COLLECT_SOURCES", raising=False)

    with pytest.raises(ValueError, match=error):
        run(module, monkeypatch, write_manifest(tmp_path / "m.json", sha256=sha256, url=url), tmp_path / "out")


TARBALL = b"tini source"
DEBIAN = b"glibc ubuntu patches"
DSC = f"""Format: 3.0 (quilt)
Source: glibc
Checksums-Sha256:
 {hashlib.sha256(TARBALL).hexdigest()} {len(TARBALL)} glibc_2.23.orig.tar.xz
 {hashlib.sha256(DEBIAN).hexdigest()} {len(DEBIAN)} glibc_2.23-0ubuntu10.debian.tar.xz
Files:
 00000000000000000000000000000000 1 ignored
""".encode()
GLIBC = "https://launchpad.net/ubuntu/+archive/primary/+sourcefiles/glibc/2.23-0ubuntu10"


def write_spdx(path: Path, *packages: dict) -> Path:
    path.write_text(json.dumps({"spdxVersion": "SPDX-2.3", "packages": list(packages)}))
    return path


def spdx_package(name: str, version: str, url: str, body: bytes | None) -> dict:
    checksums = [{"algorithm": "SHA256", "checksumValue": hashlib.sha256(body).hexdigest()}] if body is not None else []
    return {
        "name": name,
        "versionInfo": version,
        "downloadLocation": url,
        "checksums": checksums,
        "licenseConcluded": "MIT",
    }


def serve(module, monkeypatch: pytest.MonkeyPatch, files: dict[str, bytes]) -> None:
    monkeypatch.setattr(module.urllib.request, "urlopen", lambda url, timeout: Response(files[url]))


def run_spdx(module, monkeypatch: pytest.MonkeyPatch, output: Path, *args: str) -> int:
    monkeypatch.setattr(sys, "argv", [str(SCRIPT), *args, "--output", str(output)])
    return module.main()


def test_spdx_packages_are_collected_and_cover_what_syft_reports(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = load_module()
    monkeypatch.setenv("NHX_COLLECT_SOURCES", "1")
    url = "https://github.com/krallin/tini/archive/refs/tags/v0.19.0.tar.gz"
    serve(module, monkeypatch, {url: TARBALL})
    spdx = write_spdx(tmp_path / "tini.spdx.json", spdx_package("tini", "0.19.0", url, TARBALL))
    output = tmp_path / "out"

    assert run_spdx(module, monkeypatch, output, "--spdx", str(spdx)) == 0

    assert (output / "pinned" / "tini-0.19.0.tar.gz").read_bytes() == TARBALL
    assert (output / "manifests" / "downloaded-pinned-sources.txt").read_text() == (
        f"tini==0.19.0\ttini-0.19.0.tar.gz\t{url}\tMIT\tUnknownPackage:tini@0.19.0,binary:tini@0.19.0\n"
    )


def test_a_dsc_brings_the_files_it_lists(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    module = load_module()
    monkeypatch.setenv("NHX_COLLECT_SOURCES", "1")
    dsc = f"{GLIBC}/glibc_2.23-0ubuntu10.dsc"
    serve(
        module,
        monkeypatch,
        {
            dsc: DSC,
            f"{GLIBC}/glibc_2.23.orig.tar.xz": TARBALL,
            f"{GLIBC}/glibc_2.23-0ubuntu10.debian.tar.xz": DEBIAN,
        },
    )
    spdx = write_spdx(tmp_path / "tini.spdx.json", spdx_package("glibc", "2.23-0ubuntu10", dsc, DSC))
    output = tmp_path / "out"

    assert run_spdx(module, monkeypatch, output, "--spdx", str(spdx)) == 0

    assert (output / "pinned" / "glibc-2.23-0ubuntu10.dsc").read_bytes() == DSC
    assert (output / "pinned" / "glibc_2.23.orig.tar.xz").read_bytes() == TARBALL
    assert (output / "pinned" / "glibc_2.23-0ubuntu10.debian.tar.xz").read_bytes() == DEBIAN


def test_a_dsc_file_that_does_not_match_its_checksum_fails(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    module = load_module()
    monkeypatch.setenv("NHX_COLLECT_SOURCES", "1")
    dsc = f"{GLIBC}/glibc_2.23-0ubuntu10.dsc"
    serve(
        module,
        monkeypatch,
        {
            dsc: DSC,
            f"{GLIBC}/glibc_2.23.orig.tar.xz": b"tampered",
            f"{GLIBC}/glibc_2.23-0ubuntu10.debian.tar.xz": DEBIAN,
        },
    )
    spdx = write_spdx(tmp_path / "tini.spdx.json", spdx_package("glibc", "2.23-0ubuntu10", dsc, DSC))

    with pytest.raises(RuntimeError, match="sha256 mismatch"):
        run_spdx(module, monkeypatch, tmp_path / "out", "--spdx", str(spdx))


def test_an_spdx_package_without_a_checksum_must_be_skipped(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    module = load_module()
    monkeypatch.delenv("NHX_COLLECT_SOURCES", raising=False)
    git = "git+https://github.com/docker-library/busybox@fd0ca34e75d3f1aba2da4955a0f8e049aba8f7fe"
    spdx = write_spdx(tmp_path / "busybox.spdx.json", spdx_package("docker-library-busybox", "fd0ca34", git, None))

    with pytest.raises(ValueError, match="invalid sha256"):
        run_spdx(module, monkeypatch, tmp_path / "out", "--spdx", str(spdx))

    assert (
        run_spdx(
            module, monkeypatch, tmp_path / "out", "--spdx", str(spdx), "--skip-spdx-package", "docker-library-busybox"
        )
        == 0
    )


def test_release_archives_are_named_after_the_component() -> None:
    module = load_module()
    source = module.PinnedSource(
        name="kaniko",
        version="1.28.5",
        license="Apache-2.0",
        url="https://github.com/osscontainertools/kaniko/archive/refs/tags/v1.28.5.tar.gz",
        sha256="0" * 64,
        covers=(),
    )

    assert source.filename == "kaniko-1.28.5.tar.gz"
