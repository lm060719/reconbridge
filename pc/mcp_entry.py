"""PyInstaller 冻结入口。

冻结环境没有 `python -m reconbridge_mcp` 这样的模块入口，PyInstaller 需要一个具体脚本作为
程序入口。这里直接转调包内 server.main（它自己会分派 `--register` 与正常起 MCP server）。
"""
from reconbridge_mcp.server import main

if __name__ == "__main__":
    main()
