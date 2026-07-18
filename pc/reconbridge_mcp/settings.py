"""ReconBridge MCP —— 运行配置。

所有配置走环境变量，便于在 Claude Code 的 mcp 配置里注入；给出合理默认值。
"""
from __future__ import annotations

import os
import shutil
from pathlib import Path

# 项目根：pc/ 的上一级
PKG_DIR = Path(__file__).resolve().parent
PC_DIR = PKG_DIR.parent
PROJECT_ROOT = PC_DIR.parent


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


class Settings:
    # 传输方式：adb（USB，经 adb forward 到设备 127.0.0.1，推荐）| wifi（局域网直连）
    transport: str = _env("RECONBRIDGE_TRANSPORT", "adb").lower()

    # adb 相关
    serial: str = _env("RECONBRIDGE_SERIAL", "")  # 多设备时指定；为空用唯一设备
    adb: str = _env("RECONBRIDGE_ADB", "") or (
        shutil.which("adb")
        or str(Path(os.environ.get("LOCALAPPDATA", "")) / "Android/Sdk/platform-tools/adb.exe")
    )

    # 连接参数
    port: int = int(_env("RECONBRIDGE_PORT", "8787") or "8787")
    # wifi 模式下必填；adb 模式下自动 = http://127.0.0.1:<port>
    url: str = _env("RECONBRIDGE_URL", "")
    # token：为空时 adb 模式会自动从设备读取
    token: str = _env("RECONBRIDGE_TOKEN", "")

    # 设备上模块路径
    rbctl: str = _env("RECONBRIDGE_RBCTL", "/data/adb/modules/reconbridge/rbctl")
    device_conf: str = _env("RECONBRIDGE_DEVICE_CONF", "/data/adb/reconbridge/config.conf")

    # 工作目录：拉包、反编译产物落盘处
    workdir: Path = Path(_env("RECONBRIDGE_WORKDIR", "") or (PC_DIR / "work"))

    # 外部工具（为空时按 pc/tools 下的默认位置或 PATH 探测，见 external.py）
    jadx: str = _env("RECONBRIDGE_JADX", "")
    ghidra: str = _env("RECONBRIDGE_GHIDRA", "")  # Ghidra 安装根目录
    tools_dir: Path = PC_DIR / "tools"

    # 重型原生工具（Ghidra / JDK）必须放 ASCII 路径——Ghidra 的 log4j 初始化在含中文/非 ASCII
    # 的安装路径下会崩。项目本身在含中文的“逆向模块”目录下，故这类工具放到同盘 ASCII 目录。
    native_tools_dir: Path = Path(
        _env("RECONBRIDGE_NATIVE_TOOLS", "")
        or (PROJECT_ROOT.drive + "/ReconBridgeTools")
    )

    # 网络超时（秒）
    timeout: float = float(_env("RECONBRIDGE_TIMEOUT", "600") or "600")


settings = Settings()
settings.workdir.mkdir(parents=True, exist_ok=True)
