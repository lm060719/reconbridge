# Native 实时配置验证

基线：`0623acd717a1439aa8bd66382b4a959851742933`。本批实现在线新增、行为停用和替换。
物理撤钩与真机测试未执行，功能边界见 [NATIVE_LIVE.md](../../../../pc/NATIVE_LIVE.md)。

| 验证 | 原始记录 |
|---|---|
| Python，193 passed | [pc-tests.txt](pc-tests.txt) |
| C++ 真实分派/在途调用/并发配置 | [cpp-tests.txt](cpp-tests.txt) |
| NDK r27c 双架构 | [native-build.txt](native-build.txt) |
| 模块 ZIP 与四个二进制指纹 | [artifacts.json](artifacts.json) |

Linux CI 额外运行 daemon socketpair 集成测试：使用真实 handler 验证首次握手期间的配置替换/删除、
在线追加/删除、Runtime 状态回传与旧 Java H 帧兼容。对应 Actions 完整日志见提交关联的运行记录。
