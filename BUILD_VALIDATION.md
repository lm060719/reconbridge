# 跨平台构建与验证

## PC 工具启动

jadx/Ghidra 在 Linux/macOS 直接执行脚本，不经过 `cmd.exe`。确保解压后的启动脚本具有执行权限。
Windows `.bat/.cmd` 使用带完整参数引用的 cmd 启动，支持空格、中文及 `&` 等路径；
包含 `%`、双引号或换行的批处理参数会被明确拒绝，避免被 cmd 展开为其他内容。

外部工具设置仍可使用 `RECONBRIDGE_JADX`、`RECONBRIDGE_GHIDRA` 和 `RECONBRIDGE_NATIVE_TOOLS`。
Linux/macOS 的默认 native 工具目录是 `~/.local/share/ReconBridge/tools`；Windows 保留同盘的
`ReconBridgeTools`。macOS `jdk-21*.jdk/Contents/Home` 也可自动识别。
adb 查找优先级：显式配置 → PATH → ANDROID_HOME/ANDROID_SDK_ROOT → 当前系统 SDK 默认目录。

资源限制的返回值以 `memory_limit_enforced` 为准。macOS 不施加 RLIMIT_AS，返回 false；
超时终止进程组、日志大小、并发限制与 JVM `-Xmx` 仍然生效。JVM 堆上限不等于整个进程内存上限。

## 从源码构建模块

需要 Python 3.10+ 和 Android NDK。本项目 CI 固定使用 **r27c / 27.2.12479018**。

```text
python scripts/build_native.py --ndk <NDK目录>
python scripts/package_module.py --output dist/ReconBridge-verified.zip
python scripts/package_module.py --verify dist/ReconBridge-verified.zip
```

也可设置 `ANDROID_NDK_HOME`，省略 `--ndk`。默认构建两种 ABI；单独构建可用
`--abi arm64-v8a` 或 `--abi x86_64`。构建过程不覆盖 `module/` 的旧二进制：

```text
build/native/arm64-v8a/
  bin/reconbridge_daemon
  zygisk/arm64-v8a.so
  build-manifest.json
build/native/x86_64/
  bin/reconbridge_daemon_x86_64
  zygisk/x86_64.so
  build-manifest.json
```

打包器仅从这两个构建目录取 daemon/Zygisk，从 `m3/prebuilt/` 取 Hook 引擎库，
从 `module/` 取脚本和 WebUI，不会误用 `module/bin`、`module/zygisk` 的旧产物。

构建清单记录源码指纹、NDK/API 版本和二进制 SHA-256。打包前检查：

- 两种 ABI 均存在，源码指纹与当前代码匹配；
- NDK/API 版本一致，文件长度与 SHA-256 匹配；
- daemon、Zygisk、Hook 引擎都是对应架构的 64 位小端 ELF；
- ZIP 没有重复项、绝对路径或目录穿越，全部内容与包内清单一致；
- 设备脚本使用 LF 换行。

先验证临时 ZIP，再替换目标包。验证失败会保留已有目标包。校验用于发现构建/打包错误，
不代替发布签名或真机兼容性验证。

## CI

[工作流](.github/workflows/pc-tests.yml) 包含：

| Job | 检查 |
|---|---|
| pytest | Windows/Linux/macOS 的 Python 测试、真实测试启动脚本、自动工具清单一致性 |
| tracer | Kotlin 单元测试与 debug APK 构建 |
| daemon-syntax | C++ 语法、事件/JNI/native 状态、实时配置分派与实际 socket 协议集成测试 |
| native | 固定 NDK 下分别构建 arm64-v8a/x86_64 的 daemon 与 Zygisk |
| module-package | 等待以上检查成功，再收集新构建产物、打包、校验并上传 ZIP |

启动脚本测试使用可控的小脚本验证参数传递，不下载真实 jadx/Ghidra 做完整反编译。
工作流上传的是构建 artifact，不会自动发布 Release 或部署手机。

本地回归：

```text
cd pc
python -m pytest -q --ignore=test_mobile_mcp_e2e.py
python ../scripts/generate_tool_catalog.py --check
```

真机验证单独进行；本轮按用户要求未连接/部署设备，JNI 运行时兼容性仍待验证。

`native-abi` 在 Linux ARM64 与 x86_64 实际执行生产汇编网关（混合参数、栈参数、浮点替换、特殊值、异常展开），是模块打包的前置检查。源码指纹包括 `.S` 汇编。

JNI 回归在 daemon-syntax 中运行观察器、生命周期/地址检查与真实 ELF 导出解析，socket 集成测试覆盖注册、替换、注销和断线。
