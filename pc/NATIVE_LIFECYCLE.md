# Native v3：撤钩、槽位回收与库生命周期

更新 daemon 与两种 ABI 的 Zygisk 模块，并重启目标进程。`runtime_hook_status` 中
`native_status_version: 3` 表示新执行器；daemon `/health.capabilities.jni_mappings` 为 3。
PC/手机工具数没有增加，仍通过现有 unhook、runtime_hook_status、inspect_jni_bindings 和事件接口使用。

## 物理撤钩

`unhook(package, hook_id)` 仍先更新配置。新调用停止采集与篡改，在途调用保留其进入时的配置。
维护线程等待该入口的在途计数归零，再调用 ShadowHook unhook 或 DobbyDestroy 恢复目标指令。
不会在持有 linker 锁时等待业务调用，否则业务方法内部的 dlopen/dlclose 可能死锁。

| 状态 | 含义 |
|---|---|
| `draining` | 仍有在途调用，尚未物理撤钩；维护线程继续检查 |
| `removed` | 引擎撤钩成功，或未安装的 pending 项已取消；逻辑槽位可回收 |
| `unhook_failed` | 引擎撤钩失败，保留槽位和入口记录，不假定目标已恢复 |
| `unloaded` + `engine_handle_quarantined` | 库先离开且没有完成正常撤钩；隔离旧句柄，绝不向旧地址写回指令 |

HTTP 投递成功不代表上述流程完成。查看 runtime 的 `physical_unhook`、`live_unhook`、
`slots_used`、`hooks` 和 `retained_hooks`。PC diagnose_target 会提示未完成撤钩及 loader 能力缺失。
原配置之外最多返回最近 128 条历史；底层状态缓存淘汰计数为 `history_evicted`。

正常撤钩成功后，同一逻辑槽位可用于不同 Hook 点，不再受“进程一生最多 64 个不同点”限制。
同时占用（含 draining/失败保留）的逻辑槽位仍最多 64 个。满额整体换点时，先删除、等回收，再新增。
同一尚保留点仍不允许修改 ABI；确认回收后可以重新配置，但声明必须匹配函数实际原型。

## 延迟入口与资源保留

每次新安装拥有独立的 RX 入口和不可变上下文，携带槽位代次。旧线程即使在跳转后被暂停，
恢复时也不会读到新槽位所有者的签名、原函数或行为。正常撤钩后的延迟入口调用恢复后的地址，
不会使用已释放的引擎跳板。库已失效时不会再跳入旧地址；原始返回寄存器置零，不声明该业务调用成功。

为覆盖“已经跳转但还没有进入 C++ 计数区”的线程，入口页及上下文留到进程退出，最多 4096 个。
这与 64 个可复用的逻辑槽位不同。达到入口上限时明确报错，需重启进程。
入口先 RW 写入，再切为 RX，不保留 RWX 页。引擎自身跳板内存由引擎管理；当前固定 Dobby
实现恢复代码后仍保留内部记录/重定位内存，因此本功能不声称释放全部引擎内存。
运行期间反复装卸的内存开销需要在真机长时间测试中验收。

## 持续库卸载观察

所有安装/撤钩按 linker → 生命周期 → 入口锁的顺序串行化。记录完整路径、加载基址、可执行区间
和加载代次；不同路径的同名库不混为一个目标，同 basename 同时可见时拒绝猜测安装位置。

- **ARM64**：注册 ShadowHook linker fini-pre/init-post 回调。fini 前尝试撤钩，发出
  `native_library_unloading`；后续快照确认消失或观察到新代次加载后发出 `native_library_unloaded`。
  fini 并不立即等同于已经 unmap，同地址同路径重载也获得新代次。
- **x86_64**：拦截 Bionic `__loader_dlclose`，在同一 linker 临界区取前后快照，检查真正消失的库及依赖。
  失败 close 或只减少引用计数不会产生卸载结论。调用原函数的参数、返回值和 errno 保留，析构函数内
  的嵌套 dlclose 也被观察。Dobby 没有 fini 回调，close 前会暂时撤掉已无在途调用的受管补丁，
  存活库在维护线程恢复安装；期间可能漏采。相同存活库重新安装复用其入口记录。
- 两种 ABI 均每 150 ms 核对已加载 ELF，并安装等待中的目标。尚未加载的库保持 pending；
  库已加载但符号连续 200 次无法解析会报告失败。卸载重载后，仍在期望配置中的目标重新安装。
  安装由维护线程完成，因此不保证捕获库构造函数及加载后首次维护之前的调用。

能力必须看 `loader.status`、`continuous` 和 `mechanism`；回调/符号不可用时报告 partial/unavailable，
不能把轮询降级当成完整连续观察。回调事件先进入 1024 项队列，维护线程再发送；丢弃计数见
`loader.events_dropped`。上游丢失仍未知，不能据此宣称全量捕获。

raw munmap、自定义加载器不属于 linker 回调覆盖范围。x86_64 非 dlclose 路径（如部分 TLS 延迟释放）
依赖快照，极短时间的卸载/同址重载可能漏过。应用在函数仍执行时卸载其代码本身不安全；执行器
遇到这种情况会隔离旧句柄，不尝试在地址消失后恢复代码，后续引擎冲突可能需要重启。

## JNI 映射失效

daemon 收到同一连接的库卸载事件后，仅对路径/可执行区间吻合的旧注册标记
`module_unloading` / `module_unloaded`。JNI 和 loader 事件使用共同的单调观察序号；
延迟送达的旧卸载不能覆盖在该边界之后的新注册，同地址重新加载也不会复活旧绑定。
缺少顺序信息的旧事件不参与这种推断；映射仍是观察历史，`current_bindings_verified=false`。

## 验证

宿主回归覆盖在途调用、异常退出、失败撤钩、延迟入口、2,000 次逻辑槽位复用、状态缓存边界、
引用计数 close、fini 与 unmap 分离、同址重载、依赖卸载及 JNI 事件乱序/连接隔离。
CI 在两种 CPU 上执行生产 RX 入口和汇编网关；x86_64 额外编译固定版本 Dobby，实际安装/撤钩
100 次并核对目标原始指令。NDK 构建两种 Android ABI，daemon socket 测试验证卸载事件进入 JNI 状态。
按用户约定，本轮不连接或部署 Android 真机。

实现依据：[ShadowHook API](https://github.com/bytedance/android-inline-hook/blob/main/doc/manual.md)、
[固定版本 DobbyDestroy](https://github.com/jmpews/Dobby/blob/5dfc8546954ce3b3198132ab13fddb89ee92cdd7/source/dobby.cpp)、
[Bionic loader 锁与 dlclose](https://android.googlesource.com/platform/bionic/+/master/linker/dlfcn.cpp)。
