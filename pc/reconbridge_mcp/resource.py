"""重型本地工具的统一资源治理。

所有 jadx / Ghidra / Hermes / Androguard worker 都通过这里启动：
- 全局限制重型任务并发数；
- stdout/stderr 流式写临时日志，只把尾部读回内存；
- Windows 用 Job Object 限制整个子进程树的提交内存；
- POSIX 用 RLIMIT_AS 限制进程及其后代的虚拟地址空间。
"""
from __future__ import annotations

import ctypes
import os
import re
import signal
import subprocess
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Optional, Sequence

from .settings import settings

_HEAVY_SEMAPHORE = threading.BoundedSemaphore(max(1, settings.heavy_max_parallel))


@dataclass
class LimitedProcessResult:
    returncode: int
    log_tail: str
    timed_out: bool = False
    memory_limit_enforced: bool = False


def java_memory_env(base: Optional[Mapping[str, str]], memory_mb: int) -> dict[str, str]:
    """给 JVM 留出 native/metaspace 余量，堆默认使用任务硬上限的 70%。"""
    env = dict(base or os.environ)
    heap_mb = max(256, int(max(256, memory_mb) * 0.70))
    current = env.get("JAVA_TOOL_OPTIONS", "")
    current = re.sub(r"(?:^|\s)-Xmx\S+", "", current).strip()
    env["JAVA_TOOL_OPTIONS"] = (current + f" -Xmx{heap_mb}m").strip()
    return env


def _read_tail(path: Path, max_bytes: int) -> str:
    try:
        size = path.stat().st_size
        with path.open("rb") as fp:
            if size > max_bytes:
                fp.seek(-max_bytes, os.SEEK_END)
            data = fp.read()
        return data.decode("utf-8", errors="replace")
    except Exception:
        return ""


def _posix_preexec(memory_bytes: int):
    def apply_limit() -> None:
        import resource

        resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))

    return apply_limit


def _create_windows_job(memory_bytes: int):
    from ctypes import wintypes

    class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_longlong),
            ("PerJobUserTimeLimit", ctypes.c_longlong),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class IO_COUNTERS(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_ulonglong),
            ("WriteOperationCount", ctypes.c_ulonglong),
            ("OtherOperationCount", ctypes.c_ulonglong),
            ("ReadTransferCount", ctypes.c_ulonglong),
            ("WriteTransferCount", ctypes.c_ulonglong),
            ("OtherTransferCount", ctypes.c_ulonglong),
        ]

    class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
            ("IoInfo", IO_COUNTERS),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    JOB_OBJECT_LIMIT_JOB_MEMORY = 0x00000200
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
    JobObjectExtendedLimitInformation = 9

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    kernel32.SetInformationJobObject.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    kernel32.SetInformationJobObject.restype = wintypes.BOOL

    job = kernel32.CreateJobObjectW(None, None)
    if not job:
        return None

    info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
    info.BasicLimitInformation.LimitFlags = (
        JOB_OBJECT_LIMIT_JOB_MEMORY | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    )
    info.JobMemoryLimit = memory_bytes
    ok = kernel32.SetInformationJobObject(
        job,
        JobObjectExtendedLimitInformation,
        ctypes.byref(info),
        ctypes.sizeof(info),
    )
    if not ok:
        kernel32.CloseHandle(job)
        return None
    return job


def _assign_windows_job(job, proc: subprocess.Popen) -> bool:
    if not job:
        return False
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    return bool(kernel32.AssignProcessToJobObject(job, wintypes.HANDLE(int(proc._handle))))


def _close_windows_handle(handle) -> None:
    if not handle:
        return
    ctypes.WinDLL("kernel32", use_last_error=True).CloseHandle(handle)


def run_limited(
    cmd: Sequence[str],
    *,
    timeout: float,
    memory_mb: int,
    env: Optional[Mapping[str, str]] = None,
    cwd: Optional[str | os.PathLike[str]] = None,
) -> LimitedProcessResult:
    """运行重型子进程，并确保日志和内存都有上限。"""
    memory_mb = max(256, int(memory_mb))
    memory_bytes = memory_mb * 1024 * 1024
    log_bytes = max(16, settings.process_log_tail_kb) * 1024

    with _HEAVY_SEMAPHORE:
        fd, log_name = tempfile.mkstemp(prefix="reconbridge-", suffix=".log")
        os.close(fd)
        log_path = Path(log_name)
        job = None
        proc: Optional[subprocess.Popen] = None
        enforced = False
        timed_out = False

        try:
            with log_path.open("wb") as log_fp:
                kwargs = {
                    "stdout": log_fp,
                    "stderr": subprocess.STDOUT,
                    "env": dict(env) if env is not None else None,
                    "cwd": cwd,
                }
                if os.name == "nt":
                    kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
                else:
                    kwargs["preexec_fn"] = _posix_preexec(memory_bytes)
                    kwargs["start_new_session"] = True

                proc = subprocess.Popen(list(cmd), **kwargs)

                if os.name == "nt":
                    job = _create_windows_job(memory_bytes)
                    enforced = _assign_windows_job(job, proc)
                    if job and not enforced:
                        _close_windows_handle(job)
                        job = None
                else:
                    enforced = True

                try:
                    proc.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    timed_out = True
                    if os.name == "nt":
                        if job:
                            _close_windows_handle(job)
                            job = None
                        if proc.poll() is None:
                            proc.kill()
                    else:
                        try:
                            os.killpg(proc.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                    proc.wait()

            return LimitedProcessResult(
                returncode=proc.returncode if proc else -1,
                log_tail=_read_tail(log_path, log_bytes),
                timed_out=timed_out,
                memory_limit_enforced=enforced,
            )
        finally:
            if job:
                _close_windows_handle(job)
            try:
                log_path.unlink()
            except OSError:
                pass
