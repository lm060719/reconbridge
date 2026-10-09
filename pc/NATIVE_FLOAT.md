# Native float / double

更新 daemon 与 Zygisk 模块，并重启目标进程后使用。
`runtime_hook_status(package)` 的 Native 连接回报 `native_float_abi.version: 1` 表示支持。
支持 Android arm64-v8a / x86_64 的普通标量函数，最多 8 个参数；可采集、替换参数和替换返回值。

## 完整签名与逻辑参数

假设目标为 `double sample(int64_t count, float factor, double bias, void* context)`：

```python
post_hook({
    "package": "com.example.app", "mode": "append", "restart": False,
    "targets": [{
        "id": "native_fp", "kind": "native", "lib": "libsample.so", "symbol": "sample",
        "signature": {"args": ["int64", "float", "double", "ptr"], "ret": "double"},
        "capture": {
            "args": [{"index": 0, "type": "int"}, {"index": 1, "type": "float"},
                     {"index": 2, "type": "double"}],
            "ret": {"capture": True, "type": "double"}
        },
        "action": {"type": "replace_arg", "arg_overrides": [{"index": 1, "value": 1.25}]}
    }]
})
```

`signature.args` 必须列出所有参数，含不采集的参数。`index` 从 0 开始，表示函数声明中的位置。
执行器根据签名分别映射整数与浮点寄存器；x86_64 的第 7、8 个整数类参数由栈传递。
`signature` 中 `int` / `int64` 表示 64 位整数，`ptr` 表示指针，`float` / `double` 表示 IEEE binary32 / binary64。
`ret` 另可为 `void`，此时不能采集或替换返回值。指针内容仍用 capture 的 `string` / `bytes` 读取。

不含浮点的旧配置可继续省略 signature，沿用最多 8 个机器字参数的旧约定。
包含浮点的函数必须声明完整签名，即使只采集其中的整数参数。
执行器无法从符号名验证真实 C/C++ 原型；签名必须与目标一致。

替换返回值可使用 `"action": {"type": "replace_ret", "ret_value": 2.5}`。
替换数值必须有限，float 不可超出 binary32 范围；转换时采用正常浮点舍入，微小数值可能下溢。
返回值采集记录原函数结果，发生在返回值替换之前；参数采集记录传入原函数的替换后参数。

## 事件与运行中更新

有限值携带 `value` 数字与 `bits` 十六进制原始位模式，例如：

```json
{"index": 1, "type": "float", "value": 1.25, "bits": "0x3fa00000"}
```

NaN / 无穷大使用合法 JSON，并保留原始位模式：

```json
{"type": "double", "value": null, "special": "+inf", "bits": "0x7ff0000000000000"}
```

`special` 可为 `nan`、`+inf`、`-inf`；负零由 `bits` 准确区分。
NaN payload 保留在 bits 中；不支持通过替换配置注入 NaN / Inf。

实时替换采集与 action 的行为见 [Native 实时配置](NATIVE_LIVE.md)。
同一保留 hook 点的签名不能更改，即使先停用再启用；更改签名需重启进程。
禁用后仍按原签名透传浮点参数/返回值。在途调用保持进入时的配置版本。

## 范围与验证

不支持可变参数、超过 8 个参数、结构体/联合体（含 HFA）、SIMD 向量、long double、
隐藏结构体返回地址或自定义调用约定；也不支持 Windows x64 ABI。
非静态 C++ 方法的隐式 `this` 指针必须计入参数，JNI 函数的隐式参数也必须列入。
`signature.variadic: true`、不支持的类型、浮点采集类型不匹配会在配置阶段拒绝。
省略这些声明无法让执行器自动识别不支持的真实原型。

实现参考 [AAPCS64](https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst) 和
[x86-64 psABI](https://gitlab.com/x86-psABIs/x86-64-ABI)。
`tests/native_abi_test.cpp` 在 Linux ARM64 / x86_64 上执行生产汇编网关与编译器生成的真实函数，
覆盖混合参数、8 个浮点参数、整数栈参数、替换、透传、特殊值与异常展开。
NDK 另编译两种 Android ABI。以上不等于 Android 真机 Hook 引擎验证；本轮按用户要求暂缓真机。
