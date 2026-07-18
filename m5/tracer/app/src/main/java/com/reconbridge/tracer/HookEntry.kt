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

        var installed = 0
        for (i in 0 until targets.length()) {
            val t = targets.optJSONObject(i) ?: continue
            if (t.optString("kind", "native") != "java") continue  // native 目标由 M3 执行器负责
            try {
                installed += installJavaHook(lpparam, io, t)
            } catch (th: Throwable) {
                log("[$pkg] 目标#$i (${t.optString("class")}.${t.optString("method")}) 安装失败: $th")
            }
        }
        if (installed > 0) log("[$pkg] 装上 $installed 个 java hook") else vlog("[$pkg] 无 java 目标")
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

    /** 渲染一个值：tostring（数值/布尔原样，其余 toString 截断）/ class（类名）/ json（原样字符串，交 PC 解析）。 */
    private fun render(v: Any?, mode: String, max: Int): Any {
        if (v == null) return JSONObject.NULL
        return when (mode) {
            "class" -> v.javaClass.name
            "json" -> truncate(v.toString(), max)
            else -> when (v) {
                is Number, is Boolean -> v
                is CharSequence -> truncate(v.toString(), max)
                else -> truncate(v.toString(), max)
            }
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
}
