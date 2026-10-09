# JNI 映射完善验证

基线：`6a00515f133128b0b8489d2643a14d3a499a3123`。
接口、状态和覆盖限制见 [JNI_MAPPINGS.md](../../../../pc/JNI_MAPPINGS.md)。

| 验证 | 原始输出 |
|---|---|
| Python 195 passed / 1 skipped，工具清单 95 / 49 | [pc-tests.txt](pc-tests.txt) |
| JNI 假表、弱类身份、生命周期、ELF/地址检查；真实双 ABI ELF 解析 | [cpp-tests.txt](cpp-tests.txt) |
| NDK r27c 双架构 daemon / Zygisk | [native-build.txt](native-build.txt) |
| 模块打包与独立校验 | [package.txt](package.txt) |
| 源码、二进制及模块 ZIP 哈希 | [artifacts.json](artifacts.json) |

主要命令（从仓库根目录，Python 使用 pc/.venv）：

```text
cd pc && python -m pytest -q
python scripts/generate_tool_catalog.py --check
cl /std:c++17 /EHsc /utf-8 /O2 tests/jni_mappings_test.cpp
cl /std:c++17 /EHsc /utf-8 /O2 /Isrc /I<JDK/include> /I<JDK/include/win32> tests/jni_observer_test.cpp
mappings.exe
observer.exe
clang++ --target=<aarch64|x86_64>-linux-android26 -shared -fPIC tests/jni_exports_fixture.cpp -o <fixture.so>
mappings.exe <fixture.so>
python scripts/build_native.py --ndk <android-ndk-r27c>
python scripts/package_module.py --output dist/ReconBridge-jni-mappings.zip
python scripts/package_module.py --verify dist/ReconBridge-jni-mappings.zip
```

观察器回归包括原函数返回值/待处理异常保持、重入、同对象不同 JNI handle、同名不同类、
弱引用回收后 ID 不复用、1024 类身份容量耗尽时明确回报身份未知。
映射测试覆盖重注册替换、注销、回收、断线、跨连接隔离和缓存淘汰；
导出测试覆盖转义/Unicode/重载、未定义与隐藏符号排除、畸形 ELF 边界和真实 NDK 产物。

原始 C++ 日志保留一次 MSVC 测试桩宏与系统头文件声明冲突的失败输出；
将 mutex 系统头移到测试宏之前后修复，后续观察器测试（含最终容量测试）通过。

CI 执行新增真实 socket JNI 生命周期测试，以及 Linux 编译的 ELF 样本解析；
其余三平台 Python、Tracer、双 CPU Native ABI、NDK 和模块校验继续执行。
推送后完整 CI 日志保存为 `dist/jni-mappings-ci.log`，合并验证及提交日志保存为
`dist/jni-mappings-complete.log`。最终 CI 结果以本次提交关联的 Actions 为准。

未执行 Android 真机 Hook 验收；持续 linker 卸载通知与 VM 历史绑定枚举未实现。
