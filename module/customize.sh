#!/system/bin/sh
# ReconBridge 安装脚本（KernelSU / Magisk 通用）

ui_print "- 安装 ReconBridge 逆向传输层 M1"

# 架构检查：本模块支持 arm64-v8a（shadowhook）与 x86_64（Dobby，见
# m3/dobby-android-build-fix.patch）。Magisk/KernelSU 的 $ARCH 里 x86_64 记作 "x64"。
case "$ARCH" in
  arm64|x64) ;;
  *)
    ui_print "! 当前架构为 $ARCH，本模块仅支持 arm64-v8a / x86_64"
    abort  "! 安装中止"
    ;;
esac

# 按架构落地 system/lib64 下的 hook 引擎库（打包时按架构分放在
# system_lib64_arm64/ 与 system_lib64_x64/ 两个 staging 目录，这里选一个
# 合并进真正会被挂载到 /system/lib64 的 system/lib64/，另一个连同 staging
# 目录一起删掉，避免把另一种架构的 ELF 也挂进 /system/lib64）。
mkdir -p "$MODPATH/system/lib64"
if [ "$ARCH" = "arm64" ] && [ -d "$MODPATH/system_lib64_arm64" ]; then
  cp -f "$MODPATH"/system_lib64_arm64/*.so "$MODPATH/system/lib64/" 2>/dev/null
elif [ "$ARCH" = "x64" ] && [ -d "$MODPATH/system_lib64_x64" ]; then
  cp -f "$MODPATH"/system_lib64_x64/*.so "$MODPATH/system/lib64/" 2>/dev/null
fi
rm -rf "$MODPATH/system_lib64_arm64" "$MODPATH/system_lib64_x64"

# 按架构选守护进程二进制（daemon 是单个原生可执行文件，不像 zygisk/<abi>.so
# 那样由框架自动按 ABI 选择，这里手动落地成统一的 bin/reconbridge_daemon）。
if [ "$ARCH" = "x64" ] && [ -f "$MODPATH/bin/reconbridge_daemon_x86_64" ]; then
  rm -f "$MODPATH/bin/reconbridge_daemon"
  mv "$MODPATH/bin/reconbridge_daemon_x86_64" "$MODPATH/bin/reconbridge_daemon"
else
  rm -f "$MODPATH/bin/reconbridge_daemon_x86_64"
fi

# 二进制存在性检查
if [ ! -f "$MODPATH/bin/reconbridge_daemon" ]; then
  ui_print "! 缺少守护进程二进制 bin/reconbridge_daemon（当前架构 $ARCH）"
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

# M3：Zygisk 动态 hook 层（zygisk/<abi>.so 由 ZygiskNext 按进程实际 ABI 自动
# 挑选，两个架构的 .so 可以共存于包内，这里只是设权限，不用按 $ARCH 筛选）。
if [ -f "$MODPATH/zygisk/arm64-v8a.so" ] || [ -f "$MODPATH/zygisk/x86_64.so" ]; then
  ui_print "- 检测到 Zygisk 动态 hook 层（M3）"
  [ -f "$MODPATH/zygisk/arm64-v8a.so" ] && set_perm "$MODPATH/zygisk/arm64-v8a.so" 0 0 0644
  [ -f "$MODPATH/zygisk/x86_64.so" ]    && set_perm "$MODPATH/zygisk/x86_64.so"    0 0 0644
  if [ ! -d /data/adb/modules/zygisksu ] && [ ! -d /data/adb/modules/rezygisk ] && \
     ! ls -d /data/adb/modules/*zygisk* >/dev/null 2>&1; then
    ui_print "! 未检测到 Zygisk 实现，动态 hook(M3) 需要 ZygiskNext/ReZygisk"
  fi
fi

ui_print "- 运行目录：$DATADIR"
ui_print "- 端口默认【关闭】，重启后请在 KernelSU WebUI 中开启"
ui_print "- token 首次启动随机生成，可在 WebUI 查看"
ui_print "- 安装完成，请重启设备"
