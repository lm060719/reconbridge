# Native Hook 运行中配置

更新 daemon 和 Zygisk 模块后，先给目标配置 Hook，再启动目标进程。
`runtime_hook_status(package)` 中 `kind: native` 且 `live_reconcile: true` 的连接支持本功能。
没有在线 Native Runtime 时，首次注入仍需重启/启动目标。

## 新增、替换与停用

```python
post_hook({"package": "com.example.app", "restart": False, "mode": "append",
           "targets": [{"id": "native_sample", "kind": "native", "lib": "libsample.so",
                        "symbol": "sample", "action": {"type": "replace_ret", "ret_value": 1}}]})
runtime_hook_status("com.example.app")
# 同 id 再 post_hook(mode="append") 可替换参数、返回值或采集配置。
unhook("com.example.app", "native_sample")
runtime_hook_status("com.example.app")
```

`post_hook(mode="replace")` 下发全量期望配置；`append` 按 ID 合并。
`hot_injected` / `hot_unhooked` 统计成功投递的 Runtime **连接数**，不保证引擎已经安装成功。
响应的 `runtime_effect_confirmed: false` 提醒调用方通过 Runtime 状态确认。
一个 Android 进程可能同时有 Java 与 Native 两条连接。

| 操作 | 实际效果 |
|---|---|
| 新 Hook 点 | 分配稳定槽位并安装；等待库加载时报告 pending |
| 同一点修改行为或 ID | 复用原跳板，用新配置处理后续调用 |
| 同 ID 移到另一点 | 原点停用并等待撤钩，新点安装；状态分别显示在 retained_hooks/hooks |
| 删除 | 新调用先透传，v3 在途调用结束后物理撤钩并回收逻辑槽位 |
| 重新启用同一点 | 尚未撤钩时复用；已回收后分配新的入口代次 |
| 无效配置、重复 ID/同点多目标、容量不足 | 整批配置不切换，configuration.failed 保留错误和 retained_previous_config |

配置校验通过后才发布完整不可变快照。每次调用在进入时选定一个版本，一直持有到返回。
**已经进入的调用仍可能按旧配置修改结果和发出事件**；停用确认不代表所有在途调用已结束。
事件中的 `native_config_revision` 与 Runtime 的 `config_revision` 用于区分这些版本。
引擎安装失败按 Hook 独立报告，不回滚其他已生效的 Hook；完整快照原子切换仅指配置行为。

## 状态与边界

- v3 的 `hooks` 列当前配置，`retained_hooks` 列撤钩/卸载历史；检查 removed、draining、unhook_failed。
- v3 `removal_mode: physical_after_drain`，引擎撤钩成功后回收槽位；v2 仍仅 passthrough。
- 同时最多占用 64 个逻辑槽位，正常撤钩后可以复用。独立入口记录最多 4096 个并保留到进程退出。
- 同一地址的不同符号/offset 别名不保证能共同安装，最终以引擎结果为准。
- 解析/安装失败可删除并待回收后重新添加；物理撤钩失败会保留槽位，不重复使用可能已经失效的引擎句柄。
- 进程退出或通道断开后不自动重连；已安装行为保持最后配置，新的配置需等下次连接/启动。
- JNI 观察器仍按启动配置安装；变更时 `configuration.jni_restart_required: true`，需要重启。
- float / double 需完整签名，见 [Native 浮点支持](NATIVE_FLOAT.md)；同一保留点不可运行中更改签名。
- v3 增加库卸载跟踪及重载安装，机制和能力缺失见 `loader`。installed 仍不是全量运行正确性的证明。
- 锁顺序、入口保留、x86_64 close 期间漏采及覆盖边界见 [NATIVE_LIFECYCLE.md](NATIVE_LIFECYCLE.md)。

## 实现与验证

Native 通过 `H` 帧声明类型，后台读取 `R` 完整配置，使用 `S` 回报状态。
daemon 在 H 握手后补发最新磁盘配置（配置已删除则发空 targets），覆盖首次取配置与注册之间的更新窗口。
配置读/合并/写入/下发使用同一把锁，避免并发 append 丢失或发送顺序倒置。

引擎接口参考：[ShadowHook 手册](https://github.com/bytedance/android-inline-hook/blob/main/doc/manual.md)、
[Dobby 拦截器实现](https://github.com/jmpews/Dobby/blob/master/source/Interceptor.h)。
v3 对在途调用计数并延迟撤钩，用独立代次入口防止槽位复用串线；引擎修改在 linker 锁下串行化。
引擎内部内存释放依赖引擎实现，Android 兼容性仍需真机验收。

`tests/native_live_test.cpp` 执行真实配置管理器与代理分派逻辑，验证并发更新与在途调用。
`tests/native_ipc_test.cpp` 使用真实 daemon handler 和 socketpair，验证追加、删除、握手窗口与旧 Java H 兼容。
这些宿主测试不安装 Android 机器码 Hook，真机验收仍需单独进行。
