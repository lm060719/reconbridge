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
        "list_hooks", "runtime_hook_status", "runtime_state_get", "runtime_state_set",
        "runtime_state_remove", "runtime_state_increment", "runtime_state_append",
        "runtime_state_clear", "runtime_event_emit", "runtime_context_status",
        "runtime_activity_action", "unhook", "collect_events", "capture_scenario",
        "list_scenarios", "diff_scenarios", "recent_events", "trace_java",
        "patch_java", "dump_dex", "list_dumps", "list_artifacts",
        "toolchain_status", "open_target", "investigation_status", "prepare_index",
        "prepare_target", "search_target", "investigate", "inspect_method",
        "inspect_call_graph", "verify_call_path", "capture_call_graph_scenario",
        "list_call_graph_scenarios", "diff_call_graph_scenarios",
        "analyze_scenario_divergence", "capture_divergence_probe",
        "compare_divergence_probes", "inspect_condition_origin",
        "verify_condition_writer", "inspect_value_lineage",
        "verify_value_lineage", "compare_value_lineage_runtime",
        "rank_root_causes", "verify_root_cause_hypothesis",
        "compare_root_cause_hypothesis", "rank_candidates",
        "verify_candidates",
        "trace_target", "evidence_graph",
        "explain_evidence", "close_investigation",
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
            assert len(tools) >= 64
            names = {t.name for t in tools}
            assert "device_status" in names
            assert "toolchain_status" in names
            assert "runtime_hook_status" in names
            assert "runtime_state_get" in names
            assert "runtime_state_set" in names
            assert "runtime_state_remove" in names
            assert "runtime_state_increment" in names
            assert "runtime_state_append" in names
            assert "runtime_state_clear" in names
            assert "runtime_event_emit" in names
            assert "runtime_context_status" in names
            assert "runtime_activity_action" in names
            assert "open_target" in names
            assert "search_target" in names
            assert "prepare_index" in names
            assert "investigate" in names
            assert "inspect_method" in names
            assert "inspect_call_graph" in names
            assert "verify_call_path" in names
            assert "capture_call_graph_scenario" in names
            assert "list_call_graph_scenarios" in names
            assert "diff_call_graph_scenarios" in names
            assert "analyze_scenario_divergence" in names
            assert "capture_divergence_probe" in names
            assert "compare_divergence_probes" in names
            assert "inspect_condition_origin" in names
            assert "verify_condition_writer" in names
            assert "inspect_value_lineage" in names
            assert "verify_value_lineage" in names
            assert "compare_value_lineage_runtime" in names
            assert "rank_root_causes" in names
            assert "verify_root_cause_hypothesis" in names
            assert "compare_root_cause_hypothesis" in names
            assert "rank_candidates" in names
            assert "verify_candidates" in names
            assert "trace_target" in names
            assert "evidence_graph" in names
            assert "explain_evidence" in names

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
