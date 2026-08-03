package com.reconbridge.tracer

import android.os.Build
import android.util.Log
import de.robv.android.xposed.XC_MethodHook.MethodHookParam
import org.json.JSONArray
import org.json.JSONObject
import org.mozilla.javascript.ScriptableObject
import java.io.File
import java.io.InputStream
import java.lang.reflect.Constructor
import java.lang.reflect.Field
import java.lang.reflect.Member
import java.lang.reflect.Method
import java.lang.reflect.Modifier
import java.nio.ByteBuffer
import java.util.Base64

private const val TAG = "ActionExecutor"

/**
 * Action 执行上下文：记录当前 Hook 调用的参数、返回值、this 对象、ClassLoader 以及局部寄存器变量。
 */
class ActionContext(
    val param: MethodHookParam,
    val classLoader: ClassLoader,
    val pkg: String,
) {
    val registers = HashMap<String, Any?>()

    var thisObject: Any?
        get() = param.thisObject
        set(value) {
            param.thisObject = value
        }

    val args: Array<Any?>?
        get() = param.args

    var result: Any?
        get() = param.result
        set(value) {
            param.result = value
        }
}

object ActionExecutor {

    /**
     * 执行指定 phase (before | after) 的 action 配置（支持单步或流水线列表）。
     */
    fun executeActions(
        ctx: ActionContext,
        actionObj: JSONObject?,
        phase: String
    ) {
        if (actionObj == null) return

        // 1. 支持按 phase 分离的 callback: action.before_actions / action.after_actions
        val phaseKey = if (phase == "before") "before_actions" else "after_actions"
        val phaseActions = actionObj.optJSONArray(phaseKey)
        if (phaseActions != null) {
            runPipeline(ctx, phaseActions)
        }

        // 2. 通用步骤列表 action.steps (在指定 phase 触发，默认在 before 时运行 steps)
        val steps = actionObj.optJSONArray("steps")
        val stepsPhase = actionObj.optString("steps_phase", "before")
        if (steps != null && stepsPhase == phase) {
            runPipeline(ctx, steps)
        }

        // 3. 兼容原有标量属性: replace_args, skip_original (before 阶段), replace_return (after 或 skip_original 时)
        if (phase == "before") {
            val replaceArgs = actionObj.optJSONArray("replace_args")
            if (replaceArgs != null) {
                applyReplaceArgs(ctx, replaceArgs)
            }
            if (actionObj.optBoolean("skip_original", false)) {
                val replaceReturn = actionObj.optJSONObject("replace_return")
                ctx.result = if (replaceReturn != null) resolveValue(ctx, replaceReturn) else null
            }
        } else if (phase == "after") {
            val skipOriginal = actionObj.optBoolean("skip_original", false)
            val replaceReturn = actionObj.optJSONObject("replace_return")
            if (!skipOriginal && replaceReturn != null) {
                ctx.result = resolveValue(ctx, replaceReturn)
            }
        }
    }

    private fun runPipeline(ctx: ActionContext, steps: JSONArray) {
        for (i in 0 until steps.length()) {
            val step = steps.optJSONObject(i) ?: continue
            try {
                executeStep(ctx, step)
            } catch (t: Throwable) {
                Log.e(TAG, "[${ctx.pkg}] 执行 Step $i (${step.optString("action")}) 失败: $t", t)
            }
        }
    }

    private fun executeStep(ctx: ActionContext, step: JSONObject) {
        val type = step.optString("action")
        when (type) {
            "call_method", "invoke" -> stepCallMethod(ctx, step)
            "set_field" -> stepSetField(ctx, step)
            "construct", "new_instance" -> stepConstruct(ctx, step)
            "exec_shell", "shell" -> stepExecShell(ctx, step)
            "eval_js", "js" -> stepEvalJs(ctx, step)
            "eval_dex", "dex" -> stepEvalDex(ctx, step)
            "set_arg" -> stepSetArg(ctx, step)
            "set_result" -> stepSetResult(ctx, step)
            else -> Log.w(TAG, "[${ctx.pkg}] 未知 action 类型: $type")
        }
    }

    // ------------------------------------------------------------------------
    // 1. 调用 Java 方法 (call_method)
    // ------------------------------------------------------------------------
    private fun stepCallMethod(ctx: ActionContext, step: JSONObject) {
        val targetExpr = step.optString("target", "this")
        val targetObj = resolveTarget(ctx, targetExpr)
        val methodName = step.optString("method")
        if (methodName.isEmpty()) return

        val argsArr = step.optJSONArray("args")
        val paramsArr = step.optJSONArray("params")

        val argValues = ArrayList<Any?>()
        if (argsArr != null) {
            for (i in 0 until argsArr.length()) {
                val argObj = argsArr.get(i)
                argValues.add(resolveValueItem(ctx, argObj))
            }
        }

        val method: Method = if (paramsArr != null) {
            val paramTypes = Array(paramsArr.length()) { i ->
                resolveType(ctx.classLoader, paramsArr.getString(i))
            }
            findMethod(targetObj, methodName, paramTypes)
                ?: throw NoSuchMethodException("$targetExpr.$methodName(指定参数)")
        } else {
            findMethodByArgs(targetObj, methodName, argValues)
                ?: throw NoSuchMethodException("$targetExpr.$methodName(${argValues.size}个参数)")
        }

        method.isAccessible = true
        val invTarget = if (Modifier.isStatic(method.modifiers)) null else (targetObj as? TargetInstance)?.instance ?: targetObj
        val ret = method.invoke(invTarget, *argValues.toArray())

        val saveTo = step.optString("save_to")
        if (saveTo.isNotEmpty()) {
            ctx.registers[saveTo] = ret
        }
    }

    // ------------------------------------------------------------------------
    // 2. 修改对象字段 (set_field)
    // ------------------------------------------------------------------------
    private fun stepSetField(ctx: ActionContext, step: JSONObject) {
        val targetExpr = step.optString("target", "this")
        val fieldName = step.optString("field")
        if (fieldName.isEmpty()) return

        val valueObj = step.opt("value")
        val valToSet = resolveValueItem(ctx, valueObj)

        val targetObj = resolveTarget(ctx, targetExpr)
        val clazz = when (targetObj) {
            is TargetClass -> targetObj.clazz
            is TargetInstance -> targetObj.instance?.javaClass ?: throw IllegalArgumentException("Target instance is null")
            null -> throw IllegalArgumentException("Target is null")
            else -> targetObj.javaClass
        }

        val field = findField(clazz, fieldName) ?: throw NoSuchFieldException("Class ${clazz.name} 无字段 $fieldName")
        field.isAccessible = true

        val invTarget = if (Modifier.isStatic(field.modifiers)) null else (targetObj as? TargetInstance)?.instance ?: targetObj
        field.set(invTarget, valToSet)
    }

    // ------------------------------------------------------------------------
    // 3. 构造复杂对象 (construct / new_instance)
    // ------------------------------------------------------------------------
    private fun stepConstruct(ctx: ActionContext, step: JSONObject) {
        val className = step.optString("class")
        if (className.isEmpty()) return
        val clazz = ctx.classLoader.loadClass(className)

        val argsArr = step.optJSONArray("args")
        val paramsArr = step.optJSONArray("params")

        val argValues = ArrayList<Any?>()
        if (argsArr != null) {
            for (i in 0 until argsArr.length()) {
                argValues.add(resolveValueItem(ctx, argsArr.get(i)))
            }
        }

        val ctor: Constructor<*> = if (paramsArr != null) {
            val paramTypes = Array(paramsArr.length()) { i ->
                resolveType(ctx.classLoader, paramsArr.getString(i))
            }
            clazz.getDeclaredConstructor(*paramTypes)
        } else {
            findConstructorByArgs(clazz, argValues)
                ?: throw NoSuchMethodException("Class $className 没有匹配 ${argValues.size} 个参数的构造函数")
        }

        ctor.isAccessible = true
        val obj = ctor.newInstance(*argValues.toArray())

        val saveTo = step.optString("save_to")
        if (saveTo.isNotEmpty()) {
            ctx.registers[saveTo] = obj
        }
    }

    // ------------------------------------------------------------------------
    // 4. 执行 Shell 命令 (exec_shell)
    // ------------------------------------------------------------------------
    private fun stepExecShell(ctx: ActionContext, step: JSONObject) {
        val cmdObj = step.opt("cmd") ?: return
        val asRoot = step.optBoolean("as_root", false)

        val cmdList = ArrayList<String>()
        if (asRoot) {
            cmdList.add("su")
            cmdList.add("-c")
            if (cmdObj is JSONArray) {
                val sb = StringBuilder()
                for (i in 0 until cmdObj.length()) {
                    if (i > 0) sb.append(" ")
                    sb.append(cmdObj.getString(i))
                }
                cmdList.add(sb.toString())
            } else {
                cmdList.add(cmdObj.toString())
            }
        } else {
            if (cmdObj is JSONArray) {
                for (i in 0 until cmdObj.length()) {
                    cmdList.add(cmdObj.getString(i))
                }
            } else {
                cmdList.add("sh")
                cmdList.add("-c")
                cmdList.add(cmdObj.toString())
            }
        }

        val proc = ProcessBuilder(cmdList).redirectErrorStream(true).start()
        val outText = proc.inputStream.bufferedReader().use { it.readText() }
        proc.waitFor()

        val saveTo = step.optString("save_to")
        if (saveTo.isNotEmpty()) {
            ctx.registers[saveTo] = outText.trim()
        }
    }

    // ------------------------------------------------------------------------
    // 5. 执行 JavaScript 代码片段 (eval_js) - 集成 Rhino 引擎
    // ------------------------------------------------------------------------
    private fun stepEvalJs(ctx: ActionContext, step: JSONObject) {
        val script = step.optString("script")
        if (script.isEmpty()) return

        val jsCtx = org.mozilla.javascript.Context.enter()
        try {
            jsCtx.optimizationLevel = -1 // Android 上关闭 JIT 字节码生成，走解释执行模式
            val scope: ScriptableObject = jsCtx.initStandardObjects()

            // 绑定变量: $this, $args, $ret, $ctx, $regs
            ScriptableObject.putProperty(scope, "\$this", org.mozilla.javascript.Context.javaToJS(ctx.thisObject, scope))
            ScriptableObject.putProperty(scope, "\$args", org.mozilla.javascript.Context.javaToJS(ctx.args, scope))
            ScriptableObject.putProperty(scope, "\$ret", org.mozilla.javascript.Context.javaToJS(ctx.result, scope))
            ScriptableObject.putProperty(scope, "\$ctx", org.mozilla.javascript.Context.javaToJS(ctx, scope))
            ScriptableObject.putProperty(scope, "\$regs", org.mozilla.javascript.Context.javaToJS(ctx.registers, scope))

            val res = jsCtx.evaluateString(scope, script, "<m5_script>", 1, null)
            val javaRes = when (res) {
                null, is org.mozilla.javascript.Undefined -> null
                is org.mozilla.javascript.Wrapper -> res.unwrap()
                else -> res
            }

            val saveTo = step.optString("save_to")
            if (saveTo.isNotEmpty()) {
                ctx.registers[saveTo] = javaRes
            }
        } finally {
            org.mozilla.javascript.Context.exit()
        }
    }

    // ------------------------------------------------------------------------
    // 6. 执行 Java/Kotlin DEX 代码片段 (eval_dex)
    // ------------------------------------------------------------------------
    private fun stepEvalDex(ctx: ActionContext, step: JSONObject) {
        val dexB64 = step.optString("dex_b64")
        val dexPath = step.optString("dex_path")
        val className = step.optString("class")
        val methodName = step.optString("method", "run")

        if (className.isEmpty()) return

        val dexBytes = when {
            dexB64.isNotEmpty() -> Base64.getDecoder().decode(dexB64)
            dexPath.isNotEmpty() -> File(dexPath).readBytes()
            else -> return
        }

        val dynamicCl = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val buf = ByteBuffer.wrap(dexBytes)
            dalvik.system.InMemoryDexClassLoader(buf, ctx.classLoader)
        } else {
            val tmpDex = File.createTempFile("m5_dex_", ".dex")
            tmpDex.writeBytes(dexBytes)
            val optDir = File(tmpDex.parentFile, "opt")
            optDir.mkdirs()
            val cl = dalvik.system.DexClassLoader(tmpDex.absolutePath, optDir.absolutePath, null, ctx.classLoader)
            tmpDex.delete()
            cl
        }

        val targetClazz = dynamicCl.loadClass(className)
        val method = findMethodByArgs(targetClazz, methodName, listOf(ctx))
            ?: findMethodByArgs(targetClazz, methodName, listOf())
            ?: throw NoSuchMethodException("Class $className 无方法 $methodName")

        method.isAccessible = true
        val instance = if (Modifier.isStatic(method.modifiers)) null else targetClazz.getDeclaredConstructor().newInstance()
        val ret = if (method.parameterTypes.size == 1) {
            method.invoke(instance, ctx)
        } else {
            method.invoke(instance)
        }

        val saveTo = step.optString("save_to")
        if (saveTo.isNotEmpty()) {
            ctx.registers[saveTo] = ret
        }
    }

    // ------------------------------------------------------------------------
    // 辅助动作: set_arg & set_result
    // ------------------------------------------------------------------------
    private fun stepSetArg(ctx: ActionContext, step: JSONObject) {
        val idx = step.optInt("index", -1)
        val args = ctx.args ?: return
        if (idx in args.indices) {
            args[idx] = resolveValueItem(ctx, step.opt("value"))
        }
    }

    private fun stepSetResult(ctx: ActionContext, step: JSONObject) {
        ctx.result = resolveValueItem(ctx, step.opt("value"))
    }

    private fun applyReplaceArgs(ctx: ActionContext, replaceArgs: JSONArray) {
        val args = ctx.args ?: return
        for (i in 0 until replaceArgs.length()) {
            val r = replaceArgs.getJSONObject(i)
            val idx = r.optInt("index", -1)
            if (idx in args.indices) {
                args[idx] = resolveValue(ctx, r)
            }
        }
    }

    // ------------------------------------------------------------------------
    // 表达式与对象解析
    // ------------------------------------------------------------------------
    private class TargetClass(val clazz: Class<*>)
    private class TargetInstance(val instance: Any?)

    private fun resolveTarget(ctx: ActionContext, expr: String): Any? {
        val s = expr.trim()
        if (s == "this") return ctx.thisObject
        if (s == "ret" || s == "result") return ctx.result
        if (s.startsWith("args[")) {
            val close = s.indexOf(']')
            if (close > 0) {
                val idx = s.substring(5, close).toIntOrNull()
                val args = ctx.args
                if (idx != null && args != null && idx in args.indices) {
                    return args[idx]
                }
            }
        }
        if (s.startsWith("class:")) {
            val cName = s.substring(6)
            return TargetClass(ctx.classLoader.loadClass(cName))
        }
        if (s.startsWith("$")) {
            return ctx.registers[s]
        }
        return ctx.registers[s] ?: ctx.thisObject
    }

    private fun resolveValueItem(ctx: ActionContext, vObj: Any?): Any? {
        if (vObj is JSONObject) {
            return resolveValue(ctx, vObj)
        }
        if (vObj is String && vObj.startsWith("$")) {
            return ctx.registers[vObj]
        }
        return vObj
    }

    private fun resolveValue(ctx: ActionContext, r: JSONObject): Any? {
        if (r.has("var")) {
            return ctx.registers[r.optString("var")]
        }
        if (r.isNull("value")) return null
        val v = r.opt("value")
        val type = r.optString("type", "")
        return coerce(v, type)
    }

    private fun coerce(v: Any?, type: String): Any? {
        if (v == null) return null
        return when (type) {
            "string" -> v.toString()
            "int" -> (v as? Number)?.toInt() ?: v.toString().toIntOrNull()
            "long" -> (v as? Number)?.toLong() ?: v.toString().toLongOrNull()
            "boolean" -> (v as? Boolean) ?: v.toString().toBoolean()
            "double" -> (v as? Number)?.toDouble() ?: v.toString().toDoubleOrNull()
            "float" -> (v as? Number)?.toFloat() ?: v.toString().toFloatOrNull()
            "short" -> (v as? Number)?.toInt()?.toShort()
            "byte" -> (v as? Number)?.toInt()?.toByte()
            "char" -> v.toString().firstOrNull()
            else -> v
        }
    }

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

    private fun findMethod(targetObj: Any?, name: String, ptypes: Array<Class<*>>): Method? {
        val clazz = when (targetObj) {
            is TargetClass -> targetObj.clazz
            is TargetInstance -> targetObj.instance?.javaClass ?: return null
            null -> return null
            else -> targetObj.javaClass
        }
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

    private fun findMethodByArgs(targetObj: Any?, name: String, args: List<Any?>): Method? {
        val clazz = when (targetObj) {
            is TargetClass -> targetObj.clazz
            is TargetInstance -> targetObj.instance?.javaClass ?: return null
            null -> return null
            else -> targetObj.javaClass
        }
        var c: Class<*>? = clazz
        while (c != null) {
            for (m in c.declaredMethods) {
                if (m.name == name && m.parameterTypes.size == args.size) {
                    var match = true
                    for (i in args.indices) {
                        val arg = args[i]
                        val paramType = m.parameterTypes[i]
                        if (arg != null && !isAssignable(paramType, arg.javaClass)) {
                            match = false
                            break
                        }
                    }
                    if (match) return m
                }
            }
            c = c.superclass
        }
        return null
    }

    private fun findConstructorByArgs(clazz: Class<*>, args: List<Any?>): Constructor<*>? {
        for (ctor in clazz.declaredConstructors) {
            if (ctor.parameterTypes.size == args.size) {
                var match = true
                for (i in args.indices) {
                    val arg = args[i]
                    val paramType = ctor.parameterTypes[i]
                    if (arg != null && !isAssignable(paramType, arg.javaClass)) {
                        match = false
                        break
                    }
                }
                if (match) return ctor
            }
        }
        return null
    }

    private fun findField(clazz: Class<*>, name: String): Field? {
        var c: Class<*>? = clazz
        while (c != null) {
            try {
                return c.getDeclaredField(name)
            } catch (_: NoSuchFieldException) {
                c = c.superclass
            }
        }
        return null
    }

    private fun isAssignable(target: Class<*>, from: Class<*>): Boolean {
        if (target.isAssignableFrom(from)) return true
        if (target.isPrimitive) {
            if (target == Integer.TYPE && from == java.lang.Integer::class.java) return true
            if (target == java.lang.Long.TYPE && from == java.lang.Long::class.java) return true
            if (target == java.lang.Boolean.TYPE && from == java.lang.Boolean::class.java) return true
            if (target == java.lang.Float.TYPE && from == java.lang.Float::class.java) return true
            if (target == java.lang.Double.TYPE && from == java.lang.Double::class.java) return true
        }
        return false
    }
}
