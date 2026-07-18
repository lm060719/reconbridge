#!/system/bin/sh
# ReconBridge 安装脚本（KernelSU / Magisk 通用）

ui_print "- 安装 ReconBridge 逆向传输层 M1"

# 架构检查：本模块只提供 arm64-v8a 守护进程
if [ "$ARCH" != "arm64" ]; then
  ui_print "! 当前架构为 $ARCH，本模块仅支持 arm64-v8a"
  abort  "! 安装中止"
fi

# 二进制存在性检查
if [ ! -f "$MODPATH/bin/reconbridge_daemon" ]; then
  ui_print "! 缺少守护进程二进制 bin/reconbridge_daemon"
  ui_print "! 请先用 NDK 编译（见 README）后再打包刷入"
  abort  "! 安装中止"
fi

# 运行目录（存放 config.conf / 日志），与模块目录分离，重启保持
DATADIR=/data/adb/reconbridge
mkdir -p "$DATADIR"

ui_print "- 设置权限"
set_perm_recursive "$MODPATH" 0 0 0755 0644
set_perm "$MODPATH/bin/reconbridge_daemon" 0 0 0755
set_perm "$MODPATH/rbctl"                   0 0 0755
set_perm "$MODPATH/service.sh"              0 0 0755

# M3：Zygisk 动态 hook 层
if [ -f "$MODPATH/zygisk/arm64-v8a.so" ]; then
  ui_print "- 检测到 Zygisk 动态 hook 层（M3）"
  # ZygiskNext 会加载 zygisk/<abi>.so；companion 读 libshadowhook.so
  set_perm "$MODPATH/zygisk/arm64-v8a.so" 0 0 0644
  set_perm "$MODPATH/libshadowhook.so"    0 0 0644
  if [ ! -d /data/adb/modules/zygisksu ] && [ ! -d /data/adb/modules/rezygisk ] && \
     ! ls -d /data/adb/modules/*zygisk* >/dev/null 2>&1; then
    ui_print "! 未检测到 Zygisk 实现，动态 hook(M3) 需要 ZygiskNext/ReZygisk"
  fi
fi

ui_print "- 运行目录：$DATADIR"
ui_print "- 端口默认【关闭】，重启后请在 KernelSU WebUI 中开启"
ui_print "- token 首次启动随机生成，可在 WebUI 查看"
ui_print "- 安装完成，请重启设备"
