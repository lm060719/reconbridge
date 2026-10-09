"""UTF-8 stdio transport which preserves the process's standard handles.

The SDK's temporary TextIOWrapper objects close the underlying buffers when
collected, causing the frozen Windows bootloader's final stdout flush to fail.
Pass the existing streams explicitly instead.
"""
from __future__ import annotations

import sys

import anyio
from mcp.server.fastmcp import FastMCP
from mcp.server.stdio import stdio_server


class StreamSafeFastMCP(FastMCP):
    async def run_stdio_async(self) -> None:
        for stream in (sys.stdin, sys.stdout):
            if hasattr(stream, "reconfigure"):
                stream.reconfigure(encoding="utf-8", errors="replace")
        async with stdio_server(stdin=anyio.wrap_file(sys.stdin),
                                stdout=anyio.wrap_file(sys.stdout)) as (reader, writer):
            await self._mcp_server.run(reader, writer, self._mcp_server.create_initialization_options())
