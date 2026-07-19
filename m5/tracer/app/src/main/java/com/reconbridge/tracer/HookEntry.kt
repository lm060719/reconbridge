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
        // 全局详细日志开关：配置里 debug:true 才逐命中打日志
        traceVerbose = cfg.optBoolean("debug", false)
        vlog("[$pkg] 取到配置 ${cfgText.length} 字节 debug=$traceVerbose")
        val targets = cfg.optJSONArray("targets") ?: return

        // 已装 target id 集合（免重启热加时去重，只加不删）；线程安全供热加读线程用
        val installedIds = java.util.Collections.synchronizedSet(HashSet<String>())
        val installed = installTargets(lpparam, io, targets, installedIds)
        if (installed > 0) log("[$pkg] 装上 $installed 个 java hook") else vlog("[$pkg] 无 java 目标")

        // 免重启热加（P0-2）：声明可热加并监听 daemon 下发的新配置，收到时增量装新 target。
        // classLoader/lpparam 随闭包持久化，进程活着就能随时追加 hook，无需 force-stop 重启。
        io.enableHotReload { cfgText ->
            try {
                val newTargets = JSONObject(cfgText).optJSONArray("targets") ?: return@enableHotReload
                val added = installTargets(lpparam, io, newTargets, installedIds)
                if (added > 0) log("[$pkg] 热加装上 $added 个新 java hook")
            } catch (t: Throwable) {
                log("[$pkg] 热加解析/安装失败: $t")
            }
        }
    }

    /** 安装一批 java 目标，按 id 去重（已装的跳过——热加只加不删）。返回本次实际新装的方法数。 */
    private fun installTargets(
        lpparam: XC_LoadPackage.LoadPackageParam,
        io: InjectSocket,
        targets: JSONArray,
        installedIds: MutableSet<String>,
    ): Int {
        var installed = 0
        for (i in 0 until targets.length()) {
            val t = targets.optJSONObject(i) ?: continue
            if (t.optString("kind", "native") != "java") continue  // native 目标由 M3 执行器负责
            val id = t.optString("id", "j$i")
            if (installedIds.contains(id)) continue                // 已装，去重
            try {
                val c = installJavaHook(lpparam, io, t)
                if (c > 0) {
                    installedIds.add(id)
                    installed += c
                }
            } catch (th: Throwable) {
                log("[${lpparam.packageName}] 目标 ${t.optString("class")}.${t.optString("method")} 安装失败: $th")
            }
        }
        return installed
    }

    /** 按一个 java 目标解析类/方法/重载并挂 trace 回调，返回实际挂上的方法数。 */
    private fun installJavaHook(
        lpparam: XC_LoadPackage.LoadPackageParam,
        io: InjectSocket,
        t: JSONObject,
    ): Int {
        val cl = lpparam.classLoader
        val className = t.optString("class")
        if (className.isEmpty()) return 0
        val methodName = t.optString("method")
        val clazz = cl.loadClass(className)
        val callback = TraceCallback(io, lpparam.packageName, t)

        val paramsSpec = t.optJSONArray("params")

        if (methodName == "<init>") {
            return if (paramsSpec != null) {
                val ctor = clazz.getDeclaredConstructor(*resolveParams(cl, paramsSpec))
                XposedBridge.hookMethod(ctor, callback)
                1
            } else {
                XposedBridge.hookAllConstructors(clazz, callback).size
            }
        }

        if (methodName.isEmpty()) return 0

        return if (paramsSpec != null) {
            val m = findMethodRecursive(clazz, methodName, resolveParams(cl, paramsSpec))
                ?: throw NoSuchMethodException("$className.$methodName(指定参数)")
            XposedBridge.hookMethod(m, callback)
            1
        } else {
            XposedBridge.hookAllMethods(clazz, methodName, callback).size
        }
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
    spec: JSONObject,
) : XC_MethodHook() {

    private val id = spec.optString("id", "j")
    private val declClass = spec.optString("class")
    private val capture = spec.optJSONObject("capture") ?: JSONObject()
    private val whenPhase = capture.optString("when", "after")   // before | after | both | none

    // v2 实时篡改（可选）：action = { replace_args:[{index,value,type}], replace_return:{value,type}, skip_original }
    private val action = spec.optJSONObject("action")
    private val replaceArgs = action?.optJSONArray("replace_args")
    private val hasReplaceReturn = action?.has("replace_return") == true
    private val replaceReturn = action?.optJSONObject("replace_return")
    private val skipOriginal = action?.optBoolean("skip_original", false) ?: false
    private val tamper = replaceArgs != null || hasReplaceReturn || skipOriginal

    override fun beforeHookedMethod(param: MethodHookParam) {
        // 先按原始输入出事件，再改参数（这样事件里看到的是真实入参）
        if (whenPhase == "before" || whenPhase == "both") emit(param, "before", withRet = false)
        try {
            if (replaceArgs != null) applyReplaceArgs(param)
            if (skipOriginal) {
                // 在 before 里设 result 即可跳过原方法执行（Xposed 语义）
                param.result = if (hasReplaceReturn) coerce(replaceReturn!!) else null
                vlog("[$pkg] $id skip_original，返回被接管")
            }
        } catch (t: Throwable) {
            log("[$pkg] $id 篡改(before)失败: $t")
        }
    }

    override fun afterHookedMethod(param: MethodHookParam) {
        try {
            if (!skipOriginal && hasReplaceReturn) {
                param.result = coerce(replaceReturn!!)
                vlog("[$pkg] $id 返回值已替换")
            }
        } catch (t: Throwable) {
            log("[$pkg] $id 篡改(after)失败: $t")
        }
        // 事件里的 ret 反映最终（可能已被替换的）返回值
        if (whenPhase == "after" || whenPhase == "both") emit(param, "after", withRet = true)
    }

    /** 按声明类型把 JSON 值转成目标 Java 对象（用于替换参数/返回值）。 */
    private fun coerce(r: JSONObject): Any? {
        if (r.isNull("value")) return null
        val v = r.opt("value")
        return when (r.optString("type", "")) {
            "string" -> v?.toString()
            "int" -> (v as? Number)?.toInt() ?: v.toString().toIntOrNull()
            "long" -> (v as? Number)?.toLong() ?: v.toString().toLongOrNull()
            "boolean" -> (v as? Boolean) ?: v.toString().toBoolean()
            "double" -> (v as? Number)?.toDouble() ?: v.toString().toDoubleOrNull()
            "float" -> (v as? Number)?.toFloat() ?: v.toString().toFloatOrNull()
            "short" -> (v as? Number)?.toInt()?.toShort()
            "byte" -> (v as? Number)?.toInt()?.toByte()
            "char" -> v.toString().firstOrNull()
            else -> v   // 未指定 type：按 JSON 原生类型（String/Boolean/Integer/Double…）
        }
    }

    private fun applyReplaceArgs(param: MethodHookParam) {
        val args = param.args ?: return
        for (i in 0 until replaceArgs!!.length()) {
            val r = replaceArgs.getJSONObject(i)
            val idx = r.optInt("index", -1)
            if (idx < 0 || idx >= args.size) continue
            args[idx] = coerce(r)
            vlog("[$pkg] $id 替换 arg[$idx]")
        }
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
                        if (resolved === MISSING) {
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
        val expr = expr0.trim()
        var cur: Any?
        var s: String
        when {
            expr == "this" || expr.startsWith("this.") || expr.startsWith("this[") -> {
                cur = param.thisObject; s = expr.substring(4)
            }
            expr == "ret" || expr.startsWith("ret.") || expr.startsWith("ret[") -> {
                cur = param.result; s = expr.substring(3)
            }
            expr.startsWith("args[") -> {
                val close = expr.indexOf(']')
                if (close < 0) return MISSING
                val idx = expr.substring(5, close).toIntOrNull() ?: return MISSING
                val args = param.args
                if (args == null || idx !in args.indices) return MISSING
                cur = args[idx]; s = expr.substring(close + 1)
            }
            else -> { cur = param.thisObject; s = ".$expr" }  // 裸字段名 → this.<name>
        }
        while (s.isNotEmpty()) {
            if (cur == null) return MISSING  // 中间节点为 null，无法继续下钻
            if (s.startsWith(".")) { s = s.substring(1); continue }
            if (s.startsWith("[")) {
                val close = s.indexOf(']')
                if (close < 0) return MISSING
                val idx = s.substring(1, close).toIntOrNull() ?: return MISSING
                cur = indexInto(cur, idx)
                if (cur === MISSING) return MISSING
                s = s.substring(close + 1)
            } else {
                val cut = s.indexOfFirst { it == '.' || it == '[' }
                val name = if (cut < 0) s else s.substring(0, cut)
                s = if (cut < 0) "" else s.substring(cut)
                cur = memberOf(cur, name)
                if (cur === MISSING) return MISSING
            }
        }
        return cur
    }

    /** 取对象成员：Map.key → 反射字段（含私有/父类）→ getter（getX/x/isX）。找不到返回 MISSING。 */
    private fun memberOf(obj: Any, name: String): Any? {
        if (obj is Map<*, *>) {
            if (obj.containsKey(name)) return obj[name]
        }
        var c: Class<*>? = obj.javaClass
        while (c != null) {
            try {
                val f = c.getDeclaredField(name)
                f.isAccessible = true
                return f.get(obj)
            } catch (_: NoSuchFieldException) {
                c = c.superclass
            } catch (_: Throwable) {
                return MISSING
            }
        }
        val cap = name.replaceFirstChar { if (it.isLowerCase()) it.titlecase() else it.toString() }
        for (mName in listOf("get$cap", name, "is$cap")) {
            try {
                val m = obj.javaClass.getMethod(mName)
                m.isAccessible = true
                return m.invoke(obj)
            } catch (_: NoSuchMethodException) {
            } catch (_: Throwable) {
                return MISSING
            }
        }
        return MISSING
    }

    /** 索引进数组/List；越界或不可索引返回 MISSING。 */
    private fun indexInto(obj: Any, idx: Int): Any? {
        return try {
            when {
                obj is List<*> -> if (idx in obj.indices) obj[idx] else MISSING
                obj.javaClass.isArray -> {
                    val n = java.lang.reflect.Array.getLength(obj)
                    if (idx in 0 until n) java.lang.reflect.Array.get(obj, idx) else MISSING
                }
                else -> MISSING
            }
        } catch (_: Throwable) {
            MISSING
        }
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
