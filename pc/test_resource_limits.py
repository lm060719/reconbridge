"""重型任务资源治理单元测试。"""
from __future__ import annotations

import sys

from reconbridge_mcp.resource import java_memory_env, run_limited
from reconbridge_mcp.settings import settings


def test_java_memory_env_replaces_existing_xmx():
    env = java_memory_env({"JAVA_TOOL_OPTIONS": "-Dfile.encoding=UTF-8 -Xmx8g"}, 4096)
    assert "-Dfile.encoding=UTF-8" in env["JAVA_TOOL_OPTIONS"]
    assert "-Xmx8g" not in env["JAVA_TOOL_OPTIONS"]
    assert "-Xmx2867m" in env["JAVA_TOOL_OPTIONS"]


def test_run_limited_keeps_only_log_tail():
    result = run_limited(
        [sys.executable, "-c", "print('x' * 300000)"],
        timeout=10,
        memory_mb=256,
    )
    assert result.returncode == 0
    assert not result.timed_out
    assert len(result.log_tail.encode("utf-8")) <= settings.process_log_tail_kb * 1024 + 8
    assert result.log_tail.endswith("\n")


def test_run_limited_timeout_kills_child():
    result = run_limited(
        [sys.executable, "-c", "import time; time.sleep(5)"],
        timeout=0.05,
        memory_mb=256,
    )
    assert result.timed_out
    assert result.returncode != 0
