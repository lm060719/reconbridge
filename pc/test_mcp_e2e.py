"""通过真正的 MCP stdio 协议端到端测试 reconbridge server。
运行：.venv/Scripts/python.exe test_mcp_e2e.py
"""
import asyncio
import os
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def main():
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
            print("tools:", [t.name for t in tools])

            r = await session.call_tool("device_status", {})
            print("device_status:", r.content[0].text[:200])

            r = await session.call_tool("list_packages", {"only_third_party": True})
            import json
            data = json.loads(r.content[0].text)
            print("list_packages third-party count:", data["count"])

            r = await session.call_tool("remote_shell", {"argv": ["getprop", "ro.build.version.release"]})
            print("remote_shell:", json.loads(r.content[0].text)["stdout"].strip())

            r = await session.call_tool("toolchain_status", {})
            ts = json.loads(r.content[0].text)
            print("toolchain jadx:", bool(ts["jadx"]), "ghidra:", bool(ts["ghidra_headless"]),
                  "androguard:", ts["androguard"])
    print("E2E OK")


if __name__ == "__main__":
    asyncio.run(main())
