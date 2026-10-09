"""Explicit opt-in JNI registration observation through the native runtime."""
from .client import client
from .observability import validate_package

HOOK_ID = "__rb_jni"


def configure_jni_capture(package: str, enable: bool = True, restart: bool = False) -> dict:
    """Enable/disable observation of future successful RegisterNatives/UnregisterNatives calls.

    Requires updated daemon AND Zygisk module. Native configuration takes effect on
    NEXT process start; restart=True force-stops the app when enabling (launch it manually).
    Disabling removes desired configuration; existing observers stop only after process exit.
    Does not cover earlier registrations, Java_* static lookup, other JNI tables, or a full VM binding inventory.
    """
    validate_package(package)
    if restart and not enable:
        raise ValueError("disable removes configuration; restart the app manually to unload the observer")
    health = client.get_json("/health")
    if not health.get("capabilities", {}).get("jni_observer"):
        return {"ok": False, "error": "update daemon and Zygisk module for JNI observation"}
    if enable:
        result = client.post_json("/hook", {"package": package, "mode": "append", "restart": restart,
            "targets": [{"id": HOOK_ID, "kind": "jni"}]})
    else:
        result = client.post_json("/unhook", {"package": package, "id": HOOK_ID})
    return {**result, "hook_id": HOOK_ID, "configured": enable if result.get("ok") else None,
            "runtime_effect_confirmed": False, "requires_process_start": enable,
            "requires_process_exit": not enable,
            "next_step": "launch/restart target, then inspect_jni_bindings; check runtime_status.jni_observers"}


def inspect_jni_bindings(package: str, class_filter: str = "", limit: int = 500, include_inactive: bool = True) -> dict:
    """Read observed class/method/signature -> native address/module/offset mappings.

    Read-only: does not install a hook. Results are bounded registration history, NOT
    an enumeration of current VM bindings; registrations before capture are absent.
    Static JNI exports are separate (inspect_jni_exports). Version 2 tracks re-registration, unregister,
    weak class identity and disconnect; include_inactive=False keeps observed_registered only.
    Query-time proc maps checks do not prove that a binding remains current.
    """
    validate_package(package)
    if not 1 <= limit <= 4096:
        raise ValueError("limit must be 1..4096")
    return client.get_json("/jni/bindings", {"package": package, "class_filter": class_filter, "limit": str(limit), "include_inactive": str(include_inactive).lower()})


def inspect_jni_exports(path: str, class_filter: str = "", limit: int = 500) -> dict:
    """Inspect static Java_* export candidates from an ELF file on the device.

    Read-only; never loads the library. Requires updated daemon; ARM64/x86_64
    ELF64 little-endian .dynsym only, max 128 MiB. Sectionless ELF is unsupported.
    JNI names reveal class/method and long-name parameter descriptors, never return
    types or proof of a live binding. elf_value is relative to load bias, not a file offset.
    Use pull_libs to locate libraries; path must refer to a device file.
    """
    if not isinstance(path, str) or not path.startswith("/") or "\0" in path:
        raise ValueError("path must be an absolute device ELF path")
    if not 1 <= limit <= 4096:
        raise ValueError("limit must be 1..4096")
    return client.get_json("/jni/exports", {"path": path, "class_filter": class_filter, "limit": str(limit)})


def register(mcp) -> None:
    for tool in (configure_jni_capture, inspect_jni_bindings, inspect_jni_exports):
        mcp.tool()(tool)
