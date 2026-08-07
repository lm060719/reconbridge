"""通过真正的 MCP stdio 协议与单元测试验证 reconbridge server。
运行：pytest
"""
import asyncio
import json
import os
import sys
import pytest

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from reconbridge_mcp.client import ReconError
from reconbridge_mcp.server import (
    _pkg_dir,
    _validate_package_name,
    mcp,
    read_remote_file,
)


def test_mcp_import_and_registration():
    """验证 MCP Server 可正常导入且注册了预期工具。"""
    assert mcp.name == "reconbridge"
    tools = mcp._tool_manager.list_tools()  # noqa: SLF001
    tool_names = {t.name for t in tools}
    expected = {
        "device_status", "list_packages", "pull_apk", "pull_libs",
        "read_remote_file", "proc_info", "remote_shell", "decompile_apk",
        "dexkit_search", "ghidra_analyze", "hermes_decompile", "post_hook",
        "list_hooks", "unhook", "collect_events", "capture_scenario",
        "list_scenarios", "diff_scenarios", "recent_events", "trace_java",
        "patch_java", "dump_dex", "list_dumps", "list_artifacts",
        "toolchain_status",
    }
    assert expected.issubset(tool_names)


def test_package_name_validation():
    """验证包名校验与 Path Traversal 防护。"""
    # Valid package names
    assert _validate_package_name("com.example.app") == "com.example.app"
    assert _validate_package_name("a.b.c_1") == "a.b.c_1"

    # Invalid / Traversal package names
    invalid_pkgs = [
        "../escaped",
        "../../etc/passwd",
        "com.example/../foo",
        "C:\\Windows\\System32",
        "/absolute/path",
        "invalid name",
        "",
    ]
    for bad in invalid_pkgs:
        with pytest.raises(ReconError):
            _validate_package_name(bad)

        with pytest.raises(ReconError):
            _pkg_dir(bad, "apk")


def test_save_as_path_validation():
    """验证 read_remote_file 的 save_as 路径越界防护。"""
    invalid_save_as = [
        "../../etc/passwd",
        "../out.txt",
        "C:/Windows/System32/cmd.exe",
        "/etc/shadow",
    ]
    for bad_path in invalid_save_as:
        with pytest.raises(ReconError):
            read_remote_file(path="/system/etc/hosts", save_as=bad_path)


@pytest.mark.asyncio
async def test_mcp_stdio_e2e():
    """通过 StdioServerParameters 真正启动 MCP stdio 服务进程，并初始化 session 通信。"""
    env = dict(os.environ)
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONPATH"] = os.path.dirname(os.path.abspath(__file__))
    params = StdioServerParameters(
        command=sys.executable, args=["-m", "reconbridge_mcp"], env=env
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = (await session.list_tools()).tools
            assert len(tools) >= 25
            names = {t.name for t in tools}
            assert "device_status" in names
            assert "toolchain_status" in names

            # Test offline tool execution via stdio MCP protocol
            r = await session.call_tool("toolchain_status", {})
            assert not r.isError
            ts = json.loads(r.content[0].text)
            assert "androguard" in ts

            r_art = await session.call_tool("list_artifacts", {})
            assert not r_art.isError
            art_data = json.loads(r_art.content[0].text)
            assert "packages" in art_data


if __name__ == "__main__":
    pytest.main([__file__])
