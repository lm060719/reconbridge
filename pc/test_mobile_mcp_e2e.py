"""End-to-end test for the phone-local Streamable HTTP MCP endpoint."""

import asyncio
import json
import os
import httpx
import pytest
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client


EXPECTED_TOOLS = {
    "device_status", "list_packages", "pull_apk", "pull_libs",
    "read_remote_file", "proc_info", "remote_shell", "decompile_apk",
    "dexkit_search", "ghidra_analyze", "hermes_decompile", "post_hook",
    "list_hooks", "runtime_hook_status", "unhook", "collect_events", "capture_scenario",
    "list_scenarios", "diff_scenarios", "recent_events", "trace_java",
    "patch_java", "dump_dex", "list_dumps", "list_artifacts",
    "toolchain_status",
}


def result_json(result) -> dict:
    return json.loads(result.content[0].text)


@pytest.mark.asyncio
@pytest.mark.skipif(
    not os.environ.get("RECONBRIDGE_TOKEN"),
    reason="RECONBRIDGE_TOKEN environment variable is required for mobile MCP E2E test"
)
async def test_mobile_mcp_e2e() -> None:
    url = os.environ.get("RECONBRIDGE_MOBILE_MCP_URL", "http://127.0.0.1:8790/mcp")
    token = os.environ.get("RECONBRIDGE_TOKEN", "")

    async with httpx.AsyncClient(headers={"X-Token": token}, timeout=30) as http:
        async with streamable_http_client(url, http_client=http) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()
                names = {tool.name for tool in (await session.list_tools()).tools}
                assert names == EXPECTED_TOOLS, (EXPECTED_TOOLS - names, names - EXPECTED_TOOLS)

                status = result_json(await session.call_tool("device_status", {}))
                assert status["health"]["status"] == "ok"

                shell = result_json(await session.call_tool(
                    "remote_shell", {"argv": ["getprop", "ro.product.model"]}
                ))
                assert shell["rc"] == 0

                events = result_json(await session.call_tool(
                    "recent_events", {"limit": 2, "since_seq": 0}
                ))
                assert isinstance(events["events"], list)

                toolchain = result_json(await session.call_tool("toolchain_status", {}))
                assert bool(toolchain["jadx"]) == toolchain["mobile"]["jadx"]["ready"]
                assert bool(toolchain["ghidra_headless"]) == toolchain["mobile"]["ghidra_headless"]["ready"]

                remote_file = result_json(await session.call_tool(
                    "read_remote_file",
                    {
                        "path": "/system/etc/hosts",
                        "save_as": "mobile-mcp-e2e-hosts",
                        "max_inline_kb": 0,
                    },
                ))
                artifact = remote_file["artifact"]
                async with httpx.AsyncClient(
                    headers=artifact["download_headers"], timeout=30
                ) as download_http:
                    head = await download_http.head(artifact["download_url"])
                    assert head.status_code == 200
                    assert int(head.headers["content-length"]) == artifact["bytes"]

                    full = await download_http.get(artifact["download_url"])
                    assert full.status_code == 200
                    assert len(full.content) == artifact["bytes"]

                    partial = await download_http.get(
                        artifact["download_url"], headers={"Range": "bytes=0-7"}
                    )
                    assert partial.status_code == 206
                    assert partial.content == full.content[:8]

                async with httpx.AsyncClient(
                    headers={"Authorization": "Bearer invalid"}, timeout=30
                ) as invalid_http:
                    invalid = await invalid_http.get(artifact["download_url"])
                    assert invalid.status_code == 401


if __name__ == "__main__":
    pytest.main([__file__])
