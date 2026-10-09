"""Build fresh Android binaries with the NDK on Windows, Linux or macOS."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess

ROOT = Path(__file__).resolve().parents[1]
ABIS = {"arm64-v8a": ("aarch64-linux-android", 183, "reconbridge_daemon"),
        "x86_64": ("x86_64-linux-android", 62, "reconbridge_daemon_x86_64")}


def source_fingerprint(root: Path = ROOT) -> str:
    digest = hashlib.sha256()
    for folder in (root / "src", root / "m3/zygisk"):
        for path in sorted(folder.rglob("*")):
            if path.is_file() and path.suffix in {".cpp", ".h", ".hpp", ".S"}:
                digest.update(path.relative_to(root).as_posix().encode() + b"\0")
                digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def check_elf(data: bytes, machine: int) -> None:
    if len(data) < 64 or data[:6] != b"\x7fELF\x02\x01":
        raise ValueError("expected a 64-bit little-endian ELF")
    if int.from_bytes(data[18:20], "little") != machine:
        raise ValueError("ELF architecture does not match expected ABI")
    if int.from_bytes(data[16:18], "little") not in {2, 3}:
        raise ValueError("expected an executable/shared ELF")


def build(ndk: Path, abi: str, output: Path, api: int = 26) -> Path:
    host = {"Windows": "windows-x86_64", "Linux": "linux-x86_64", "Darwin": "darwin-x86_64"}[platform.system()]
    suffix = ".exe" if os.name == "nt" else ""
    compiler = ndk / "toolchains/llvm/prebuilt" / host / "bin" / ("clang++" + suffix)
    strip = compiler.with_name("llvm-strip" + suffix)
    if not compiler.is_file() or not strip.is_file():
        raise ValueError(f"NDK toolchain not found: {compiler}")
    triple, machine, daemon_name = ABIS[abi]
    target = output / abi
    daemon = target / "bin" / daemon_name
    zygisk = target / "zygisk" / (abi + ".so")
    daemon.parent.mkdir(parents=True, exist_ok=True)
    zygisk.parent.mkdir(parents=True, exist_ok=True)
    # A failed build must not leave a previous successful manifest publishable.
    (target / "build-manifest.json").unlink(missing_ok=True)
    initial_source = source_fingerprint()
    common = [str(compiler), f"--target={triple}{api}", "-std=c++17", "-Wall", "-Wextra", "-Wno-unused-parameter"]
    subprocess.run(common + ["-Os", "-fvisibility=hidden", "-ffunction-sections", "-fdata-sections",
        *(str(ROOT / f"src/{name}.cpp") for name in ("daemon", "dynamic", "mobile_mcp")),
        "-static-libstdc++", "-pthread", "-Wl,--gc-sections", "-Wl,--strip-all", "-o", str(daemon)], check=True)
    subprocess.run(common + ["-O2", "-fPIC", "-shared", "-I", str(ROOT / "m3/zygisk"),
        str(ROOT / "m3/zygisk/module.cpp"), str(ROOT / "m3/zygisk/native_bridge.S"), "-static-libstdc++", "-llog", "-ldl",
        "-Wl,--gc-sections", "-Wl,--exclude-libs,ALL", "-o", str(zygisk)], check=True)
    subprocess.run([str(strip), str(zygisk)], check=True)
    if initial_source != source_fingerprint():
        raise ValueError("native source changed during build; rebuild before packaging")
    files = {}
    for path in (daemon, zygisk):
        data = path.read_bytes()
        check_elf(data, machine)
        files[path.relative_to(target).as_posix()] = {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
    properties = (ndk / "source.properties").read_text(encoding="utf-8")
    revision = next(line.split("=", 1)[1].strip() for line in properties.splitlines() if line.startswith("Pkg.Revision"))
    manifest = {"abi": abi, "api": api, "ndk_revision": revision, "source_sha256": initial_source, "files": files}
    path = target / "build-manifest.json"
    path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"Built {abi}: {path}", flush=True)
    return path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ndk", type=Path, default=os.environ.get("ANDROID_NDK_HOME") or os.environ.get("ANDROID_NDK_ROOT"))
    parser.add_argument("--abi", choices=[*ABIS, "all"], default="all")
    parser.add_argument("--output", type=Path, default=ROOT / "build/native")
    args = parser.parse_args()
    if not args.ndk: parser.error("pass --ndk or set ANDROID_NDK_HOME")
    for abi in ABIS if args.abi == "all" else [args.abi]:
        build(args.ndk.resolve(), abi, args.output.resolve())
