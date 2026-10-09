import json
from pathlib import Path
import sys
import zipfile

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from build_native import ABIS, source_fingerprint
from package_module import ENGINES, STATIC, checksum, package, verify


def elf(machine):
    data = bytearray(64)
    data[:6] = b"\x7fELF\x02\x01"
    data[16:18] = (3).to_bytes(2, "little")
    data[18:20] = machine.to_bytes(2, "little")
    return bytes(data)


@pytest.fixture
def staged(tmp_path):
    repo = tmp_path / "repo"
    native = tmp_path / "build"
    (repo / "module/webroot").mkdir(parents=True)
    (repo / "m3/prebuilt").mkdir(parents=True)
    (repo / "src").mkdir()
    (repo / "src/daemon.cpp").write_text("// source\n")
    for name in STATIC:
        (repo / "module" / name).write_bytes(b"fixture\r\n")
    (repo / "module/webroot/index.html").write_text("<html></html>")
    for _, (name, machine) in ENGINES.items():
        (repo / "m3/prebuilt" / name).write_bytes(elf(machine))
    for abi, (_, machine, daemon) in ABIS.items():
        folder = native / abi
        files = {}
        for name in (f"bin/{daemon}", f"zygisk/{abi}.so"):
            path = folder / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(elf(machine))
            files[name] = checksum(path.read_bytes())
        (folder / "build-manifest.json").write_text(json.dumps({"abi": abi, "api": 26,
            "ndk_revision": "27.2.12479018", "source_sha256": source_fingerprint(repo), "files": files}))
    return repo, native, tmp_path / "module.zip"


def test_package_uses_fresh_binaries_and_normalizes_scripts(staged):
    repo, native, output = staged
    (repo / "module/bin").mkdir()
    (repo / "module/bin/reconbridge_daemon").write_bytes(b"stale-binary")
    package(native, output, repo)
    assert verify(output)["source_sha256"] == source_fingerprint(repo)
    with zipfile.ZipFile(output) as archive:
        assert archive.read("bin/reconbridge_daemon") == elf(183)
        assert b"\r" not in archive.read("rbctl")
        assert all("\\" not in name for name in archive.namelist())
    first = output.read_bytes()
    package(native, output, repo)
    assert output.read_bytes() == first


@pytest.mark.parametrize("problem", ["source", "architecture", "checksum", "missing", "toolchain"])
def test_bad_build_cannot_replace_existing_package(staged, problem):
    repo, native, output = staged
    output.write_bytes(b"previous-deliverable")
    binary = native / "arm64-v8a/bin/reconbridge_daemon"
    if problem == "source": (repo / "src/daemon.cpp").write_text("changed")
    if problem == "architecture": binary.write_bytes(elf(62))
    if problem == "checksum": binary.write_bytes(binary.read_bytes() + b"corrupt")
    if problem == "missing": binary.unlink()
    if problem == "toolchain":
        path = native / "arm64-v8a/build-manifest.json"
        manifest = json.loads(path.read_text())
        manifest["api"] = 27
        path.write_text(json.dumps(manifest))
    with pytest.raises((ValueError, FileNotFoundError)):
        package(native, output, repo)
    assert output.read_bytes() == b"previous-deliverable"


def test_verify_detects_tampered_archive(staged):
    repo, native, output = staged
    package(native, output, repo)
    with zipfile.ZipFile(output) as archive:
        content = {n: archive.read(n) for n in archive.namelist()}
    content["webroot/index.html"] = b"modified"
    with zipfile.ZipFile(output, "w") as archive:
        for name, data in content.items(): archive.writestr(name, data)
    with pytest.raises(ValueError, match="checksum"):
        verify(output)
