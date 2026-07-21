#!/system/bin/sh
# late_start service 阶段拉起 ReconBridge 守护进程。
# 守护进程常驻，但端口是否真正监听由 config.conf 里的 enabled 决定（默认关闭）。

MODDIR=${0%/*}
DATADIR=/data/adb/reconbridge
DAEMON=$MODDIR/bin/reconbridge_daemon
CONF=$DATADIR/config.conf

export PATH=/system/bin:/system/xbin:/vendor/bin:$PATH

mkdir -p "$DATADIR"

# M3：把挂到 /system/lib64 的 hook 引擎库（arm64=shadowhook，x64=dobby）
# 重打标签为 system_lib_file，否则默认 system_file 不允许 app 域 dlopen(execute)，
# 注入层加载会失败。
for L in /system/lib64/libshadowhook.so /system/lib64/libshadowhook_nothing.so /system/lib64/libdobby.so \
         "$MODDIR/system/lib64/libshadowhook.so" "$MODDIR/system/lib64/libshadowhook_nothing.so" \
         "$MODDIR/system/lib64/libdobby.so"; do
  [ -f "$L" ] && chcon u:object_r:system_lib_file:s0 "$L" 2>/dev/null
done

# 等待 /data 解密与系统就绪
i=0
while [ $i -lt 40 ]; do
  [ -d /sdcard ] && break
  sleep 2
  i=$((i + 1))
done

# 避免重复拉起
if pgrep -f reconbridge_daemon >/dev/null 2>&1; then
  exit 0
fi

if [ -x "$DAEMON" ]; then
  if command -v setsid >/dev/null 2>&1; then
    setsid "$DAEMON" "$CONF" >/dev/null 2>&1 &
  else
    nohup "$DAEMON" "$CONF" >/dev/null 2>&1 &
  fi
fi
