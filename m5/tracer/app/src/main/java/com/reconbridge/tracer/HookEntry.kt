package com.reconbridge.tracer

import android.os.Process
import android.util.Log
import de.robv.android.xposed.IXposedHookLoadPackage
import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XposedBridge
import de.robv.android.xposed.callbacks.XC_LoadPackage
import org.json.JSONArray
import org.json.JSONObject
import java.lang.reflect.Member

/** 双通道日志：android.util.Log（必进 logcat，便于 adb 观测）+ XposedBridge.log（进 LSPosed 日志）。
 *  log()：重要/低频（装 hook、错误），始终输出。 */
private fun log(msg: String) {
    Log.i(TAG, msg)
    try {
        XposedBridge.log("[$TAG] $msg")
    } catch (_: Throwable) {
    }
}

/** vlog()：逐命中/例行噪音，仅在配置 debug:true（traceVerbose）时输出。 */
private fun vlog(msg: String) {
    if (traceVerbose) log(msg)
}

/**
 * ReconBridge M5 —— 数据驱动的通用 Java trace 执行器。
 *
 * 不含任何针对特定 App 的逻辑：`handleLoadPackage` 时向守护进程要本包的 hook 配置
 * （PC 端用 post_hook / trace_java 下发），对配置里 `kind:"java"` 的目标装 trace 回调，
 * 每次命中把 this/参数/返回值/字段/调用栈序列化成事件 JSON，经同一条 socket 回传 →
 * 守护进程广播给 SSE/WS → PC 的 collect_events。
 *
 * 配置协议见 m5/JAVA_HOOK_PROTOCOL.md。
 */
private const val TAG = "ReconTracer"

class HookEntry : IXposedHookLoadPackage {

    override fun handleLoadPackage(lpparam: XC_LoadPackage.LoadPackageParam) {
        val pkg = lpparam.packageName
        vlog("handleLoadPackage 进入 pkg=$pkg process=${lpparam.processName}")

        val fetched = try {
            InjectSocket.connectAndFetch(pkg)
        } catch (t: Throwable) {
            log("[$pkg] 连守护进程异常: $t")
            null
        }
        if (fetched == null) {
            vlog("[$pkg] 无配置或连不上守护进程 → 跳过")
            return
        }

        val (io, cfgText) = fetched
        val cfg = try {
            JSONObject(cfgText)
        } catch (t: Throwable) {
            log("[$pkg] 配置解析失败: $t")
            return
        }

        traceVerbose = cfg.optBoolean("debug", false)
        vlog("[$pkg] 取到配置 ${cfgText.length} 字节 debug=$traceVerbose")

        val runtimeState = RuntimeStateStore(pkg)
        val eventBus = RuntimeEventBus()

        val registry = HookRegistry(
            packageName = pkg,
            processName = lpparam.processName,
            pid = Process.myPid(),
            initialClassLoader = lpparam.classLoader,
            installer = { target, loader ->
                installRuntimeTarget(
                    lpparam = lpparam,
                    io = io,
                    t = target,
                    classLoader = loader,
                    runtimeState = runtimeState,
                    eventBus = eventBus,
                )
            },
            onHookRemoved = { hookId ->
                runtimeState.clearHook(hookId)
                eventBus.clearOwner(hookId)
            },
        )

        lateinit var watcher: ClassLoaderWatcher

        fun publishRuntimeStatus()
        {
            val status = registry.snapshotJson()
            status.put(
                "class_loader_watch",
                watcher.snapshotJson(),
            )
            status.put(
                "runtime_state",
                runtimeState.snapshotJson(),
            )
            status.put(
                "event_bus",
                eventBus.snapshotJson(),
            )
            io.sendRuntimeStatus(status.toString())
        }

        fun afterDynamicResolution(
            stage: String,
            result: HookSyncResult,
        )
        {
            logSyncResult(pkg, stage, result)
            watcher.setPendingEnabled(registry.hasPending())
            publishRuntimeStatus()
        }

        watcher = ClassLoaderWatcher(
            shouldResolveClass = { className ->
                registry.isPendingClass(className)
            },
            onLoaderAvailable = { loader, source ->
                val sync = registry.onLoaderAvailable(
                    loader,
                    source,
                )
                afterDynamicResolution(
                    "发现动态 ClassLoader",
                    sync,
                )
            },
            onClassLoaded = { loader, className ->
                val sync = registry.onClassLoaded(
                    loader,
                    className,
                )
                afterDynamicResolution(
                    "pending 类已加载",
                    sync,
                )
            },
        )
        watcher.start()

        val initialTargets = cfg.optJSONArray("targets") ?: JSONArray()
        val initial = registry.reconcile(initialTargets)
        logSyncResult(pkg, "初始同步", initial)
        watcher.setPendingEnabled(registry.hasPending())
        publishRuntimeStatus()

        // daemon 下发的是“完整期望配置”。每次 reload 都做 reconcile；
        // 找不到类的 target 会进入 pending，并由 ClassLoaderWatcher 后续自动补装。
        io.enableHotReload { newCfgText ->
            try {
                val newCfg = JSONObject(newCfgText)
                traceVerbose = newCfg.optBoolean("debug", traceVerbose)
                val newTargets = newCfg.optJSONArray("targets") ?: JSONArray()
                val sync = registry.reconcile(newTargets)
                logSyncResult(pkg, "实时同步", sync)
                watcher.setPendingEnabled(registry.hasPending())
                publishRuntimeStatus()
            } catch (t: Throwable) {
                log("[$pkg] 实时配置同步失败: $t")
            }
        }
    }

    private fun logSyncResult(
        pkg: String,
        stage: String,
        result: HookSyncResult,
    ) {
        if (
            result.added > 0 ||
            result.replaced > 0 ||
            result.removed > 0 ||
            result.pending > 0 ||
            result.failed > 0
        ) {
            log(
                "[$pkg] $stage added=${result.added} replaced=${result.replaced} " +
                    "removed=${result.removed} unchanged=${result.unchanged} " +
                    "pending=${result.pending} failed=${result.failed}"
            )
        } else {
            vlog("[$pkg] $stage 无变化 unchanged=${result.unchanged}")
        }

        for (error in result.errors) {
            log("[$pkg] HookRegistry: $error")
        }
    }

    /** 安装 Java 方法 Hook 或纯 Runtime 事件订阅 target。 */
    private fun installRuntimeTarget(
        lpparam: XC_LoadPackage.LoadPackageParam,
        io: InjectSocket,
        t: JSONObject,
        classLoader: ClassLoader,
        runtimeState: RuntimeStateStore,
        eventBus: RuntimeEventBus,
    ): HookInstallResult {
        return if (t.optString("kind", "java") == "runtime") {
            installEventHandlers(
                pkg = lpparam.packageName,
                t = t,
                classLoader = classLoader,
                runtimeState = runtimeState,
                eventBus = eventBus,
            )
        } else {
            installJavaHook(
                lpparam = lpparam,
                io = io,
                t = t,
                classLoader = classLoader,
                runtimeState = runtimeState,
                eventBus = eventBus,
            )
        }
    }

    /**
     * 按一个 java 目标解析类/方法/重载并挂 trace 回调。
     * 方法 Hook 安装成功后，再把同一 target 的 on_event/event_handlers 订阅附加到同一生命周期。
     */
    private fun installJavaHook(
        lpparam: XC_LoadPackage.LoadPackageParam,
        io: InjectSocket,
        t: JSONObject,
        classLoader: ClassLoader,
        runtimeState: RuntimeStateStore,
        eventBus: RuntimeEventBus,
    ): HookInstallResult {
        val usingStrings = mutableListOf<String>()
        val usingArr = t.optJSONArray("using_strings")
            ?: t.optJSONObject("search")?.optJSONArray("using_strings")
            ?: t.optJSONObject("search")?.optJSONArray("strings")
        if (usingArr != null) {
            for (k in 0 until usingArr.length()) {
                val s = usingArr.optString(k)
                if (s.isNotEmpty()) {
                    usingStrings.add(s)
                }
            }
        } else {
            val singleStr = t.optString("using_strings", "")
            if (singleStr.isNotEmpty()) {
                usingStrings.add(singleStr)
            }
        }

        val base = if (usingStrings.isNotEmpty()) {
            val classFilter = t.optString("class_name_match")
                .ifEmpty { t.optString("class") }
            val methodFilter = t.optString("method_name_match")
                .ifEmpty { t.optString("method") }
            val matches = DexStringSearcher.findMatches(
                lpparam,
                usingStrings,
                classFilter,
                methodFilter,
            )
            if (matches.isEmpty()) {
                log(
                    "[${lpparam.packageName}] using_strings " +
                        "$usingStrings 未查到匹配方法"
                )
                HookInstallResult(emptyList(), emptyList())
            } else {
                log(
                    "[${lpparam.packageName}] using_strings " +
                        "$usingStrings 查到 ${matches.size} 个匹配方法"
                )
                val handles = mutableListOf<LiveHookHandle>()
                val members = mutableListOf<String>()
                for (m in matches) {
                    try {
                        val subT = JSONObject(t.toString())
                        subT.put("class", m.className)
                        subT.put("method", m.methodName)
                        if (!t.has("params")) {
                            subT.put(
                                "params",
                                JSONArray(m.paramTypes),
                            )
                        }
                        val installed = installExplicitJavaHook(
                            lpparam = lpparam,
                            io = io,
                            t = subT,
                            cl = classLoader,
                            runtimeState = runtimeState,
                            eventBus = eventBus,
                        )
                        handles.addAll(installed.handles)
                        members.addAll(installed.members)
                    } catch (th: Throwable) {
                        log(
                            "[${lpparam.packageName}] 搜索挂钩 " +
                                "${m.className}.${m.methodName} 失败: $th"
                        )
                    }
                }
                HookInstallResult(handles, members)
            }
        } else {
            installExplicitJavaHook(
                lpparam = lpparam,
                io = io,
                t = t,
                cl = classLoader,
                runtimeState = runtimeState,
                eventBus = eventBus,
            )
        }

        if (base.handles.isEmpty()) {
            return base
        }

        return attachEventHandlers(
            base = base,
            pkg = lpparam.packageName,
            t = t,
            classLoader = classLoader,
            runtimeState = runtimeState,
            eventBus = eventBus,
        )
    }

    private fun installExplicitJavaHook(
        lpparam: XC_LoadPackage.LoadPackageParam,
        io: InjectSocket,
        t: JSONObject,
        cl: ClassLoader,
        runtimeState: RuntimeStateStore,
        eventBus: RuntimeEventBus,
    ): HookInstallResult {
        val className = t.optString("class")
        if (className.isEmpty()) {
            return HookInstallResult(emptyList(), emptyList())
        }
        val methodName = t.optString("method")
        val clazz = cl.loadClass(className)
        val callback = TraceCallback(
            io = io,
            pkg = lpparam.packageName,
            classLoader = cl,
            runtimeState = runtimeState,
            eventBus = eventBus,
            spec = t,
        )

        val paramsSpec = t.optJSONArray("params")

        if (methodName == "<init>") {
            return if (paramsSpec != null) {
                val ctor = clazz.getDeclaredConstructor(
                    *resolveParams(cl, paramsSpec)
                )
                val handle = XposedBridge.hookMethod(
                    ctor,
                    callback,
                )
                HookInstallResult(
                    handles = listOf(
                        XposedLiveHookHandle(handle)
                    ),
                    members = listOf(ctor.toString()),
                )
            } else {
                val handles = XposedBridge.hookAllConstructors(
                    clazz,
                    callback,
                ).map {
                    XposedLiveHookHandle(it)
                }
                HookInstallResult(
                    handles = handles,
                    members = clazz.declaredConstructors
                        .map { it.toString() },
                )
            }
        }

        if (methodName.isEmpty()) {
            return HookInstallResult(emptyList(), emptyList())
        }

        return if (paramsSpec != null) {
            val method = findMethodRecursive(
                clazz,
                methodName,
                resolveParams(cl, paramsSpec),
            ) ?: throw NoSuchMethodException(
                "$className.$methodName(指定参数)"
            )
            val handle = XposedBridge.hookMethod(
                method,
                callback,
            )
            HookInstallResult(
                handles = listOf(
                    XposedLiveHookHandle(handle)
                ),
                members = listOf(method.toString()),
            )
        } else {
            val handles = XposedBridge.hookAllMethods(
                clazz,
                methodName,
                callback,
            ).map {
                XposedLiveHookHandle(it)
            }
            val members = clazz.declaredMethods
                .filter { it.name == methodName }
                .map { it.toString() }
            HookInstallResult(
                handles = handles,
                members = members,
            )
        }
    }

    private fun attachEventHandlers(
        base: HookInstallResult,
        pkg: String,
        t: JSONObject,
        classLoader: ClassLoader,
        runtimeState: RuntimeStateStore,
        eventBus: RuntimeEventBus,
    ): HookInstallResult {
        return try {
            val eventPart = installEventHandlers(
                pkg = pkg,
                t = t,
                classLoader = classLoader,
                runtimeState = runtimeState,
                eventBus = eventBus,
            )
            HookInstallResult(
                handles = base.handles + eventPart.handles,
                members = base.members + eventPart.members,
            )
        } catch (t: Throwable) {
            for (handle in base.handles.asReversed()) {
                try {
                    handle.unhook()
                } catch (_: Throwable) {
                }
            }
            throw t
        }
    }

    private fun installEventHandlers(
        pkg: String,
        t: JSONObject,
        classLoader: ClassLoader,
        runtimeState: RuntimeStateStore,
        eventBus: RuntimeEventBus,
    ): HookInstallResult {
        val definitions = mutableListOf<JSONObject>()
        val array = t.optJSONArray("on_event")
            ?: t.optJSONArray("event_handlers")
        if (array != null) {
            for (index in 0 until array.length()) {
                val row = array.optJSONObject(index)
                if (row != null) {
                    definitions.add(
                        JSONObject(row.toString())
                    )
                }
            }
        } else {
            val single = t.optJSONObject("on_event")
                ?: t.optJSONObject("event_handler")
            if (single != null) {
                definitions.add(
                    JSONObject(single.toString())
                )
            }
        }

        if (definitions.isEmpty()) {
            return HookInstallResult(
                emptyList(),
                emptyList(),
            )
        }

        val ownerId = t.optString("id", "runtime")
        val handles = mutableListOf<LiveHookHandle>()
        val members = mutableListOf<String>()

        try {
            for (handler in definitions) {
                val eventName = handler.optString(
                    "name",
                    handler.optString("event"),
                ).trim()
                if (eventName.isEmpty()) {
                    throw IllegalArgumentException(
                        "on_event.name 不能为空"
                    )
                }

                val handle = eventBus.subscribe(
                    ownerHookId = ownerId,
                    eventName = eventName,
                ) { event ->
                    val ctx = ActionContext(
                        param = null,
                        classLoader = classLoader,
                        pkg = pkg,
                        hookId = ownerId,
                        runtimeState = runtimeState,
                        eventBus = eventBus,
                        runtimeEvent = event,
                    )
                    ActionExecutor.executeEventHandler(
                        ctx,
                        handler,
                    )
                }
                handles.add(handle)
                members.add("event:$eventName")
            }
        } catch (t: Throwable) {
            for (handle in handles.asReversed()) {
                try {
                    handle.unhook()
                } catch (_: Throwable) {
                }
            }
            throw t
        }

        return HookInstallResult(
            handles = handles,
            members = members,
        )
    }

    private fun resolveParams(cl: ClassLoader, arr: JSONArray): Array<Class<*>> =
        Array(arr.length()) { i -> resolveType(cl, arr.getString(i)) }

    private fun resolveType(cl: ClassLoader, name: String): Class<*> = when (name) {
        "int" -> Integer.TYPE
        "long" -> java.lang.Long.TYPE
        "boolean" -> java.lang.Boolean.TYPE
        "float" -> java.lang.Float.TYPE
        "double" -> java.lang.Double.TYPE
        "short" -> java.lang.Short.TYPE
        "byte" -> java.lang.Byte.TYPE
        "char" -> Character.TYPE
        "void" -> Void.TYPE
        else -> cl.loadClass(name)
    }

    private fun findMethodRecursive(clazz: Class<*>, name: String, ptypes: Array<Class<*>>): Member? {
        var c: Class<*>? = clazz
        while (c != null) {
            try {
                return c.getDeclaredMethod(name, *ptypes)
            } catch (_: NoSuchMethodException) {
                c = c.superclass
            }
        }
        return null
    }
}

/**
 * trace 回调：按目标的 capture 配置渲染并回传事件。
 * capture = { this, args:[{index,render,max}], ret:{capture,render,max},
 *             fields:[{target,name,render,max}], stack, when(before|after|both), all_args }
 */
private class TraceCallback(
    private val io: InjectSocket,
    private val pkg: String,
    private val classLoader: ClassLoader,
    private val runtimeState: RuntimeStateStore,
    private val eventBus: RuntimeEventBus,
    spec: JSONObject,
) : XC_MethodHook() {

    private val id = spec.optString("id", "j")
    private val declClass = spec.optString("class")
    private val capture = spec.optJSONObject("capture") ?: JSONObject()
    private val whenPhase = capture.optString("when", "after")   // before | after | both | none

    private val action = spec.optJSONObject("action")
    private val tamper = action != null

    override fun beforeHookedMethod(param: MethodHookParam) {
        val ctx = ActionContext(
            param = param,
            classLoader = classLoader,
            pkg = pkg,
            hookId = id,
            runtimeState = runtimeState,
            eventBus = eventBus,
        )
        // 先按原始输入出事件，再改参数/执行 before pipeline
        if (whenPhase == "before" || whenPhase == "both") emit(param, "before", withRet = false)
        try {
            ActionExecutor.executeActions(ctx, action, "before")
        } catch (t: Throwable) {
            log("[$pkg] $id action(before) 失败: $t")
        }
    }

    override fun afterHookedMethod(param: MethodHookParam) {
        val ctx = ActionContext(
            param = param,
            classLoader = classLoader,
            pkg = pkg,
            hookId = id,
            runtimeState = runtimeState,
            eventBus = eventBus,
        )
        try {
            ActionExecutor.executeActions(ctx, action, "after")
        } catch (t: Throwable) {
            log("[$pkg] $id action(after) 失败: $t")
        }
        // 事件里的 ret 反映最终（可能已被替换/生成的）返回值
        if (whenPhase == "after" || whenPhase == "both") emit(param, "after", withRet = true)
    }


    private fun emit(param: MethodHookParam, phase: String, withRet: Boolean) {
        try {
            vlog("HIT id=$id phase=$phase method=${param.method?.name} tid=${Process.myTid()}")
            val o = JSONObject()
            if (tamper) o.put("tampered", true)
            o.put("ts", System.currentTimeMillis())
            o.put("package", pkg)
            o.put("hook_id", id)
            o.put("kind", "java")
            o.put("pid", Process.myPid())
            o.put("tid", Process.myTid())
            o.put("phase", phase)
            val member: Member? = param.method
            o.put("class", member?.declaringClass?.name ?: declClass)
            o.put("method", member?.name ?: "")

            // this
            when (capture.optString("this", "class")) {
                "none" -> {}
                "tostring" -> o.put("this", render(param.thisObject, "tostring", capture.optInt("max", 512)))
                else -> o.put("this", param.thisObject?.javaClass?.name ?: JSONObject.NULL)
            }

            // args
            val argSpec = capture.optJSONArray("args")
            val args = param.args
            if (argSpec != null && argSpec.length() > 0) {
                val arr = JSONArray()
                for (k in 0 until argSpec.length()) {
                    val a = argSpec.getJSONObject(k)
                    val idx = a.optInt("index", k)
                    val rend = a.optString("render", "tostring")
                    val max = a.optInt("max", 1024)
                    arr.put(JSONObject().apply {
                        put("index", idx)
                        put("render", rend)
                        put("value", if (idx in args.indices) render(args[idx], rend, max) else JSONObject.NULL)
                    })
                }
                o.put("args", arr)
            } else if (capture.optBoolean("all_args", false)) {
                val arr = JSONArray()
                for (k in args.indices) {
                    arr.put(JSONObject().apply {
                        put("index", k)
                        put("render", "tostring")
                        put("value", render(args[k], "tostring", 1024))
                    })
                }
                o.put("args", arr)
            }

            // ret
            if (withRet) {
                val retSpec = capture.optJSONObject("ret")
                if (retSpec != null && retSpec.optBoolean("capture", false)) {
                    o.put("ret", render(param.result, retSpec.optString("render", "tostring"), retSpec.optInt("max", 1024)))
                }
            }

            // fields（反射读私有字段，复刻 xiaoai-plug 的 getDeclaredField().isAccessible=true 做法）
            val fieldSpec = capture.optJSONArray("fields")
            if (fieldSpec != null && fieldSpec.length() > 0) {
                val farr = JSONArray()
                for (k in 0 until fieldSpec.length()) {
                    val f = fieldSpec.getJSONObject(k)
                    val target = f.optString("target", "this")
                    val name = f.optString("name")
                    val rend = f.optString("render", "tostring")
                    val max = f.optInt("max", 512)
                    val holder = when (target) {
                        "this" -> param.thisObject
                        else -> param.thisObject   // v1 仅支持 this；其它 target 留待扩展
                    }
                    farr.put(JSONObject().apply {
                        put("target", target)
                        put("name", name)
                        put("value", readField(holder, name, rend, max))
                    })
                }
                o.put("fields", farr)
            }

            // paths（嵌套字段路径捕获：直接拿深埋在 payload 对象里的值，P0-3）
            val pathSpec = capture.optJSONArray("paths")
            if (pathSpec != null && pathSpec.length() > 0) {
                val parr = JSONArray()
                for (k in 0 until pathSpec.length()) {
                    val p = pathSpec.optJSONObject(k) ?: continue
                    val expr = p.optString("path")
                    if (expr.isEmpty()) continue
                    val rend = p.optString("render", "tostring")
                    val max = p.optInt("max", 2000)
                    val entry = JSONObject().put("path", expr).put("render", rend)
                    try {
                        val resolved = resolvePath(param, expr)
                        if (resolved === ActionExecutor.MISSING) {
                            entry.put("value", JSONObject.NULL)
                            entry.put("unresolved", true)
                        } else {
                            entry.put("value", render(resolved, rend, max))
                        }
                    } catch (t: Throwable) {
                        entry.put("value", JSONObject.NULL)
                        entry.put("error", t.toString())
                    }
                    parr.put(entry)
                }
                o.put("paths", parr)
            }

            // stack
            if (capture.optBoolean("stack", false)) {
                val st = JSONArray()
                for (e in Throwable().stackTrace.take(24)) st.put(e.toString())
                o.put("stack", st)
            }

            io.sendEvent(o.toString())
        } catch (t: Throwable) {
            log("emit error: $t")
        }
    }

    /** 渲染一个值：tostring（数值/布尔原样，其余 toString 截断）/ class（类名）/
     *  json（原样字符串，交 PC 解析）/ deep（反射把对象图深度序列化成 JSON）。 */
    private fun render(v: Any?, mode: String, max: Int): Any {
        if (v == null) return JSONObject.NULL
        return when (mode) {
            "class" -> v.javaClass.name
            "json" -> truncate(v.toString(), max)
            "deep" -> try {
                deepToJson(v, DEEP_MAX_DEPTH, intArrayOf(DEEP_MAX_NODES),
                           java.util.IdentityHashMap(), max)
            } catch (t: Throwable) {
                "<deep err: $t>"
            }
            else -> when (v) {
                is Number, is Boolean -> v
                is CharSequence -> truncate(v.toString(), max)
                else -> truncate(v.toString(), max)
            }
        }
    }

    /**
     * 反射深度序列化对象图为 JSON（render:"deep"）。带三重防爆：
     *   - depth：最大递归深度（超出退化为 toString）
     *   - budget：全局节点预算（IntArray 单元素，跨递归共享，防止宽对象爆炸）
     *   - seen：IdentityHashMap 环检测
     * 容器（Map/Collection/数组）展开为 JSON object/array；枚举取 name；
     * 普通对象枚举其（含私有、跨父类）非静态字段。
     */
    private fun deepToJson(
        v: Any?, depth: Int, budget: IntArray,
        seen: java.util.IdentityHashMap<Any, Boolean>, leafMax: Int,
    ): Any {
        if (v == null) return JSONObject.NULL
        when (v) {
            is Number, is Boolean -> return v
            is CharSequence -> return truncate(v.toString(), leafMax)
        }
        if (budget[0] <= 0) return "…(达节点预算)"
        budget[0] = budget[0] - 1
        if (v is Enum<*>) return v.name
        if (depth <= 0) return truncate(v.toString(), leafMax)
        if (seen.containsKey(v)) return "<cycle>"

        when (v) {
            is Map<*, *> -> {
                seen[v] = true
                val o = JSONObject()
                for ((k, vv) in v) {
                    if (budget[0] <= 0) break
                    o.put(k?.toString() ?: "null", deepToJson(vv, depth - 1, budget, seen, leafMax))
                }
                return o
            }
            is Collection<*> -> {
                seen[v] = true
                val a = JSONArray()
                for (e in v) {
                    if (budget[0] <= 0) break
                    a.put(deepToJson(e, depth - 1, budget, seen, leafMax))
                }
                return a
            }
        }
        if (v.javaClass.isArray) {
            seen[v] = true
            val a = JSONArray()
            val n = java.lang.reflect.Array.getLength(v)
            for (i in 0 until n) {
                if (budget[0] <= 0) break
                a.put(deepToJson(java.lang.reflect.Array.get(v, i), depth - 1, budget, seen, leafMax))
            }
            return a
        }
        // 系统类（java.*/android.*）不下钻字段，避免踩到懒加载/巨型内部状态；只 toString
        val cn = v.javaClass.name
        if (cn.startsWith("java.") || cn.startsWith("javax.") || cn.startsWith("android.") ||
            cn.startsWith("kotlin.")) {
            return truncate(v.toString(), leafMax)
        }
        seen[v] = true
        val o = JSONObject()
        o.put("_class", cn)
        var c: Class<*>? = v.javaClass
        var levels = 0
        while (c != null && c != Any::class.java && levels < 6) {
            for (f in c.declaredFields) {
                if (budget[0] <= 0) break
                val mod = f.modifiers
                if (java.lang.reflect.Modifier.isStatic(mod) || f.isSynthetic) continue
                try {
                    f.isAccessible = true
                    o.put(f.name, deepToJson(f.get(v), depth - 1, budget, seen, leafMax))
                } catch (_: Throwable) {
                }
            }
            c = c.superclass
            levels++
        }
        return o
    }

    /**
     * 解析嵌套字段路径（capture.paths），直接拿深埋在 payload 对象里的值（P0-3）。
     * 语法：`args[1].payload.load_url` / `this.mState.list[0].name` / `ret.body` / 裸字段名(=this.<name>)。
     * 每段先试反射字段（含私有、跨父类），再试 getter（getX/x/isX），Map 则按 key 取；`[n]` 索引数组/List。
     * @return 解析到的原始对象（可能为 null=字段本就是 null）；无法解析返回哨兵 MISSING。
     */
    private fun resolvePath(param: MethodHookParam, expr0: String): Any? {
        val ctx = ActionContext(
            param = param,
            classLoader = classLoader,
            pkg = pkg,
            hookId = id,
            runtimeState = runtimeState,
            eventBus = eventBus,
        )
        return ActionExecutor.resolvePath(ctx, expr0)
    }

    private fun readField(holder: Any?, name: String, mode: String, max: Int): Any {
        if (holder == null || name.isEmpty()) return JSONObject.NULL
        var c: Class<*>? = holder.javaClass
        while (c != null) {
            try {
                val f = c.getDeclaredField(name)
                f.isAccessible = true
                return render(f.get(holder), mode, max)
            } catch (_: NoSuchFieldException) {
                c = c.superclass
            } catch (t: Throwable) {
                return "<read $name error: $t>"
            }
        }
        return "<no field $name>"
    }

    private fun truncate(s: String, max: Int): String =
        if (max > 0 && s.length > max) s.substring(0, max) + "…(len=${s.length})" else s

    companion object {
        /** 无法解析路径/成员时的哨兵，与“字段值本就是 null”区分开。 */
        private val MISSING = Any()
        private const val DEEP_MAX_DEPTH = 5      // deep 序列化最大递归深度
        private const val DEEP_MAX_NODES = 2000   // deep 序列化全局节点预算
    }
}
