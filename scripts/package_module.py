"""Package only freshly built ABI artifacts; verify source, hashes, ELF headers and ZIP paths."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import stat
import zipfile
from build_native import ROOT, ABIS, check_elf, source_fingerprint

STATIC = ("module.prop", "customize.sh", "service.sh", "rbctl", "sepolicy.rule")
ENGINES = {"system_lib64_arm64/libshadowhook.so": ("libshadowhook.so", 183),
           "system_lib64_arm64/libshadowhook_nothing.so": ("libshadowhook_nothing.so", 183),
           "system_lib64_x64/libdobby.so": ("libdobby_x86_64.so", 62)}


def checksum(data: bytes) -> dict:
    return {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}


def verify(path: Path) -> dict:
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)):
            raise ValueError("duplicate ZIP entries")
        for name in names:
            if "\\" in name or ":" in name or PurePosixPath(name).is_absolute() or ".." in PurePosixPath(name).parts:
                raise ValueError("unsafe ZIP path")
        manifest = json.loads(archive.read("build-manifest.json"))
        expected = set(manifest["files"]) | {"build-manifest.json"}
        if set(names) != expected:
            raise ValueError("ZIP contents differ from manifest")
        required = set(STATIC) | set(ENGINES) | {"webroot/index.html"}
        for abi, (_, machine, daemon) in ABIS.items():
            for name in (f"bin/{daemon}", f"zygisk/{abi}.so"):
                required.add(name)
                check_elf(archive.read(name), machine)
        if not required <= set(names):
            raise ValueError("incomplete module package")
        for name, (_, machine) in ENGINES.items():
            check_elf(archive.read(name), machine)
        for name, expected_hash in manifest["files"].items():
            data = archive.read(name)
            if checksum(data) != expected_hash:
                raise ValueError(f"checksum mismatch: {name}")
            if name in {"customize.sh", "service.sh", "rbctl"} and b"\r" in data:
                raise ValueError(f"Android shell script has CRLF: {name}")
        return manifest


def package(native_root: Path, output: Path, root: Path = ROOT) -> dict:
    blobs: dict[str, bytes] = {}
    builds = []
    fingerprint = source_fingerprint(root)
    for abi, (_, machine, daemon) in ABIS.items():
        folder = native_root / abi
        manifest = json.loads((folder / "build-manifest.json").read_text(encoding="utf-8"))
        if manifest["abi"] != abi or manifest["source_sha256"] != fingerprint:
            raise ValueError(f"stale or wrong-ABI build: {abi}")
        expected = {f"bin/{daemon}", f"zygisk/{abi}.so"}
        if set(manifest["files"]) != expected:
            raise ValueError(f"incomplete build manifest: {abi}")
        for name in expected:
            data = (folder / name).read_bytes()
            check_elf(data, machine)
            if checksum(data) != manifest["files"][name]:
                raise ValueError(f"build checksum mismatch: {abi}/{name}")
            blobs[name] = data
        builds.append(manifest)
    if len({(b["api"], b["ndk_revision"]) for b in builds}) != 1:
        raise ValueError("ABI builds use different NDK/API versions")
    for name in STATIC:
        blobs[name] = (root / "module" / name).read_bytes()
    for path in sorted((root / "module/webroot").rglob("*")):
        if path.is_file(): blobs[path.relative_to(root / "module").as_posix()] = path.read_bytes()
    for name, (source, machine) in ENGINES.items():
        blobs[name] = (root / "m3/prebuilt" / source).read_bytes()
        check_elf(blobs[name], machine)
    # Working copies may have CRLF even though committed scripts are LF.
    for name in STATIC:
        blobs[name] = blobs[name].replace(b"\r\n", b"\n")
    manifest = {"source_sha256": fingerprint, "builds": builds,
                "files": {name: checksum(data) for name, data in sorted(blobs.items())}}
    blobs["build-manifest.json"] = (json.dumps(manifest, indent=2) + "\n").encode()
    output.parent.mkdir(parents=True, exist_ok=True)
    # Verify before replacing an existing deliverable.
    temporary = output.with_suffix(output.suffix + ".tmp")
    try:
        with zipfile.ZipFile(temporary, "w", zipfile.ZIP_DEFLATED) as archive:
            for name, data in sorted(blobs.items()):
                entry = zipfile.ZipInfo(name, date_time=(2024, 1, 1, 0, 0, 0))
                entry.create_system = 3
                mode = 0o755 if name.startswith("bin/") or name in {"customize.sh", "service.sh", "rbctl"} else 0o644
                entry.external_attr = (stat.S_IFREG | mode) << 16
                entry.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(entry, data)
        verify(temporary)
        temporary.replace(output)
    finally:
        temporary.unlink(missing_ok=True)
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-root", type=Path, default=ROOT / "build/native")
    parser.add_argument("--output", type=Path, default=ROOT / "dist/ReconBridge-CI.zip")
    parser.add_argument("--verify", type=Path)
    args = parser.parse_args()
    if args.verify:
        verify(args.verify)
        print(f"Verified {args.verify}")
    else:
        package(args.native_root, args.output)
        print(f"Packaged and verified {args.output}")
