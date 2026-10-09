"""Generate/check the tool inventory from PC registration and mobile declarations."""
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "pc"))
from reconbridge_mcp.server import mcp


def render() -> str:
    pc = {t.name: t for t in mcp._tool_manager.list_tools()}
    source = (ROOT / "src/mobile_mcp.cpp").read_text(encoding="utf-8-sig")
    start = source.index("static const json& tools()")
    declarations = source[start:source.index("\n}", start)]
    mobile = set(re.findall(r'tool\("([^\"]+)"', declarations))
    lines = ["# MCP 工具清单", "", "由 `scripts/generate_tool_catalog.py` 自动生成。PC 来自实际注册；手机端来自源码声明，非真机探测。", "",
             f"PC：**{len(pc)}**；手机端：**{len(mobile)}**。接口及功能范围以各工具说明为准。", "",
             "| 工具 | PC | 手机 | 说明 |", "|---|---|---|---|"]
    for name in sorted(pc.keys() | mobile):
        description = pc[name].description.splitlines()[0] if name in pc else "手机端工具"
        description = description.replace("|", "\\|")
        lines.append(f"| `{name}` | {'✓' if name in pc else '—'} | {'✓' if name in mobile else '—'} | {description} |")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    output = ROOT / "pc/TOOL_CATALOG.md"
    content = render()
    if "--check" in sys.argv:
        if not output.exists() or output.read_text(encoding="utf-8") != content:
            raise SystemExit("Tool catalog is stale. Run scripts/generate_tool_catalog.py")
    else:
        output.write_text(content, encoding="utf-8")
