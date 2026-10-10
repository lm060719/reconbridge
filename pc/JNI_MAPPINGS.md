# JNI 映射：注册生命周期与静态导出

更新 daemon 和 Zygisk 模块后重启目标进程。daemon `/health` 声明 `jni_mappings: 3`、
`jni_exports: 1`；运行时 `jni_observers[].observer_version: 2` 表示生命周期观察器版本。
观察器的 `register_natives` / `unregister_natives` 分别报告安装结果，两者成功才为 `installed`，
仅一项成功为 `partial`。daemon 版本不能代替进程内观察器状态检查。

```python
configure_jni_capture("com.example.app")
# 手动重启并打开目标，触发相关 native 方法注册
inspect_jni_bindings("com.example.app", class_filter="Native", limit=500)
inspect_jni_bindings("com.example.app", include_inactive=False)

# 静态文件分析不要求启用观察器；使用设备上的独立 ELF 文件路径
inspect_jni_exports("/data/app/.../lib/arm64/libsample.so", class_filter="Native")
```

## 动态映射状态

`bindings` 保留注册记录，并根据后续观察更新 `binding_status`：

| 状态 | 含义 |
|---|---|
| `observed_registered` | 观察到成功注册，尚未观察到替换/注销/类回收/断线 |
| `superseded` | 同一类身份、方法名和签名出现新的注册 |
| `unregistered` | 同一类身份成功调用 UnregisterNatives |
| `class_collected` | 后续 JNI 观察中发现该类的弱引用已被清除 |
| `runtime_disconnected` | Runtime 通道断开；不等同于确认进程已退出 |
| `identity_unknown` | 旧观察器、身份表已满或弱引用创建失败，不能可靠归并 |
| `module_unloading` | 已观察到该库进入 fini；尚不等于已经 unmap |
| `module_unloaded` | 已观察到该库离开/被新加载代次取代；旧注册不再算活跃记录 |

类身份键包含 daemon 连接编号、进程实例和 `class_id`。不按“类名相同”归并不同 ClassLoader 的类；
PID 重用或下一次连接也不会复用旧绑定身份。`class_id` 来自弱全局引用比较，不是裸 JNI handle 地址。
弱引用不会为了观察而阻止类回收；同进程 ID 单调增加、不循环复用。
最多跟踪 1024 个仍存活的类，后续观察会清理已回收项；没有后台 GC 通知，因此回收检测可能延迟。

默认包含历史与不确定记录。`include_inactive=False` 仅保留 `observed_registered`，
它仍不是“当前有效绑定已验证”。原函数先执行，观察器仅记录成功且无 VM 待处理异常的调用；
不改变注册/注销结果，并只清理观察器自身引入的 JNI 异常。

查询同时检查地址所在的 `/proc/<pid>/maps`：

- `mapped`：当前可执行映射的路径匹配观察时的模块路径。
- `not_mapped` / `not_executable`：本次查询未发现地址映射，或所在映射不可执行。
- `module_path_mismatch` / `mapped_file_deleted`：映射路径变化，或映射文件已删除。
- `mapped_identity_unknown` / `unknown`：缺少模块身份，或进程断线、maps 不可读/不可解析。

这些是查询时的地址检查。v3 另接入持续 loader 事件，详见 [NATIVE_LIFECYCLE.md](NATIVE_LIFECYCLE.md)。APK 内嵌库的路径形式可能不一致；
同地址卸载后重载也不能仅凭 maps 识别。`current_bindings_verified` 始终为 false。
并发 VM 操作的观察完成顺序不保证等于真实绑定修改顺序，未观察到的调用和上游丢失仍未知。

映射缓存最多保留 4096 条注册记录，淘汰数见 `mapping_cache.evicted_total`；
独立生命周期事件缓存统计见 `cache`，其中还包含注销/类回收事件。
`mapping_seq` / `state_changed_seq` 属于映射状态序列，不是 SSE 游标；两个缓存分别取快照。
单次 RegisterNatives 最多采集 1024 个方法。已发生的历史注册、其他 JNI 表和未启用期间的事件不补录。

## 静态 Java_* 导出

`inspect_jni_exports` 在 PC 和手机 MCP 均可调用，对应 `GET /jni/exports`。
它只读取设备文件的 ELF `.dynsym`，不会加载库或执行目标代码。支持 ARM64 / x86_64、
ELF64 小端共享库，文件上限 128 MiB、动态符号上限 100 万、查询最多返回 4096 项。
忽略未定义导入、隐藏/局部符号和非函数导出。GNU IFUNC 会标为 `ifunc_resolver`，其值是 resolver 地址。

解析 JNI 转义（下划线、数组、对象描述符、UTF-16 Unicode）后返回类名、方法名和重载名的参数描述符。
短名称的 `parameter_descriptor` 为 null；长名称零参数为 `""`。导出名不包含返回类型，
因此 `signature` 保持 null，`return_type_known` 为 false，不推测完整 JNI 签名。

`binding_status: export_candidate` 只说明文件有该导出，不证明它已被加载、可由目标 ClassLoader 访问，
或 VM 实际采用了静态解析。`elf_value` 是 ELF 符号虚拟地址，相对于加载偏置，不是文件偏移；
普通函数运行时地址为 load bias + elf_value，IFUNC 需要额外解析实际目标。

暂不支持无 section table / 扩展 section 索引 ELF、32 位库、APK 内路径直接扫描；
此类输入明确报错。需要先提取 APK 中的 `.so` 成独立设备文件。坏格式 ELF 会经过边界检查并返回错误。

实现依据：[JNI 原生方法名称规则](https://docs.oracle.com/en/java/javase/26/docs/specs/jni/design.html#resolving-native-method-names)、
[JNI 函数与弱引用](https://docs.oracle.com/en/java/javase/11/docs/specs/jni/functions.html)。
本批验证覆盖假 JNI 表的语义保持、身份/状态回归、真实编译 ELF 和 daemon socket 协议；
Android 真机 Hook 引擎兼容性仍待验收。后续 v3 已接入 Native 物理撤钩和持续 loader 卸载观察，
JNI/loader 共同观察序号防止延迟的旧卸载误标同地址的新注册；缺少序号的旧记录不参与该推断。
