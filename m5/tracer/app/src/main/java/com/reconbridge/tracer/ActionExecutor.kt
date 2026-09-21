package com.reconbridge.tracer

import android.os.Build
import android.util.Log
import de.robv.android.xposed.XC_MethodHook.MethodHookParam
import org.json.JSONArray
import org.json.JSONObject
import org.mozilla.javascript.ScriptableObject
import java.io.File
import java.lang.reflect.Constructor
import java.lang.reflect.Field
import java.lang.reflect.Method
import java.lang.reflect.Modifier
import java.nio.ByteBuffer
import java.util.Base64

private const val TAG = "ActionExecutor"

private fun logD(msg: String) {
    try { Log.d(TAG, msg) } catch (_: Throwable) { println("[$TAG] $msg") }
}
private fun logW(msg: String) {
    try { Log.w(TAG, msg) } catch (_: Throwable) { println("[$TAG] $msg") }
}
private fun logE(msg: String, t: Throwable? = null) {
    try {
        if (t != null) Log.e(TAG, msg, t) else Log.e(TAG, msg)
    } catch (_: Throwable) {
        println("[$TAG] $msg ${t ?: ""}")
    }
}


/**
 * Action 执行上下文：记录当前 Hook 调用的参数、返回值、this 对象、ClassLoader 以及跨 before/after 共享的局部寄存器变量。
 */
internal fun getFieldAny(obj: Any, name: String): Any? {
    var c: Class<*>? = obj.javaClass
    while (c != null && c != Any::class.java) {
        try {
            val f = c.getDeclaredField(name)
            f.isAccessible = true
            return f.get(obj)
        } catch (_: NoSuchFieldException) {
            c = c.superclass
        }
    }
    return null
}

internal fun setFieldAny(obj: Any, name: String, value: Any?): Boolean {
    var c: Class<*>? = obj.javaClass
    while (c != null && c != Any::class.java) {
        try {
            val f = c.getDeclaredField(name)
            f.isAccessible = true
            f.set(obj, value)
            return true
        } catch (_: NoSuchFieldException) {
            c = c.superclass
        }
    }
    return false
}

internal class ActionContext(
    val param: MethodHookParam?,
    val classLoader: ClassLoader,
    val pkg: String,
    val hookId: String = "",
    val runtimeState: RuntimeStateStore? = null,
    val eventBus: RuntimeEventBus? = null,
    val runtimeEvent: RuntimeEvent? = null,
    val contextRuntime: RuntimeContextProvider? = null,
) {
    private var fallbackThis: Any? = null
    private var fallbackArgs: Array<Any?>? = null
    private var fallbackResult: Any? = null
    private var hasFallbackResult = false

    @Suppress("UNCHECKED_CAST")
    val registers: HashMap<String, Any?> = run {
        var regs: HashMap<String, Any?>? = null
        val methodParam = param
        if (methodParam != null) {
            try {
                regs = methodParam.getObjectExtra(
                    "recon_registers"
                ) as? HashMap<String, Any?>
            } catch (_: Throwable) {
            }
        }
        if (regs == null) {
            regs = HashMap()
            if (methodParam != null) {
                try {
                    methodParam.setObjectExtra(
                        "recon_registers",
                        regs,
                    )
                } catch (_: Throwable) {
                }
            }
        }
        regs
    }

    var thisObject: Any?
        get() {
            val methodParam = param ?: return fallbackThis
            return try {
                val value = methodParam.thisObject
                if (value != null) value else fallbackThis
            } catch (_: Throwable) {
                fallbackThis
            }
        }
        set(value) {
            fallbackThis = value
            val methodParam = param ?: return
            try {
                methodParam.thisObject = value
            } catch (_: Throwable) {
            }
        }

    val args: Array<Any?>?
        get() {
            val methodParam = param ?: return fallbackArgs
            return try {
                val value = methodParam.args
                if (value != null) value else fallbackArgs
            } catch (_: Throwable) {
                fallbackArgs
            }
        }

    var result: Any?
        get() {
            if (hasFallbackResult) {
                return fallbackResult
            }
            val methodParam = param ?: return fallbackResult
            return try {
                methodParam.result
            } catch (_: Throwable) {
                fallbackResult
            }
        }
        set(value) {
            fallbackResult = value
            hasFallbackResult = true
            val methodParam = param ?: return
            try {
                methodParam.setResult(value)
            } catch (_: Throwable) {
            }
        }
}




internal object ActionExecutor {

    val MISSING = Any()

    /**
     * 执行指定 phase (before | after) 的 action 配置（支持条件判断、返回值篡改、动作流水线与修改列表）。
     */
    fun executeActions(
        ctx: ActionContext,
        actionObj: JSONObject?,
        phase: String
    ) {
        if (actionObj == null) return

        // 缺口 2: Action 级条件检查（if / condition）
        val actionCond = actionObj.opt("condition") ?: actionObj.opt("if")
        if (actionCond != null && !evaluateCondition(ctx, actionCond)) {
            logD("[${ctx.pkg}] Action 满足跳过条件 ($phase 阶段未触发)")
            return
        }


        // 1. 按 phase 分离的 callback: action.before_actions / action.after_actions
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

        // 3. 缺口 1 & 3: 返回值 / 字段深层路径篡改 (mutate_return / mutate_fields)
        val mutateReturn = actionObj.optJSONArray("mutate_return") ?: actionObj.optJSONArray("mutate_fields")
        val mutatePhase = actionObj.optString("mutate_phase", "after")
        if (mutateReturn != null && mutatePhase == phase) {
            applyMutateReturn(ctx, mutateReturn)
        }

        // 4. 兼容原有标量属性: replace_args, skip_original (before 阶段), replace_return (after 或 skip_original 时)
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

    fun executeEventHandler(
        ctx: ActionContext,
        handler: JSONObject,
    )
    {
        val condition = handler.opt("condition") ?: handler.opt("if")
        if (
            condition != null &&
            !evaluateCondition(ctx, condition)
        ) {
            return
        }

        val actions = handler.optJSONArray("actions")
            ?: handler.optJSONArray("steps")
            ?: JSONArray()
        runPipeline(ctx, actions)
    }

    private fun runPipeline(ctx: ActionContext, steps: JSONArray) {
        for (i in 0 until steps.length()) {
            val step = steps.optJSONObject(i) ?: continue
            // 缺口 2: 单 Step 条件检查
            val stepCond = step.opt("condition") ?: step.opt("if")
            if (stepCond != null && !evaluateCondition(ctx, stepCond)) {
                continue
            }
            try {
                executeStep(ctx, step)
            } catch (t: Throwable) {
                logE("[${ctx.pkg}] 执行 Step $i (${step.optString("action")}) 失败: $t", t)
            }
        }
    }

    private fun executeStep(ctx: ActionContext, step: JSONObject) {
        val type = step.optString("action")
        when (type) {
            "call_method", "invoke" -> stepCallMethod(ctx, step)
            "set_field" -> stepSetField(ctx, step)
            "mutate", "set_path", "mutate_path" -> stepMutatePath(ctx, step)
            "construct", "new_instance" -> stepConstruct(ctx, step)
            "exec_shell", "shell" -> stepExecShell(ctx, step)
            "eval_js", "js" -> stepEvalJs(ctx, step)
            "eval_dex", "dex" -> stepEvalDex(ctx, step)
            "set_arg" -> stepSetArg(ctx, step)
            "set_result", "replace_return" -> stepSetResult(ctx, step)
            "set_state" -> stepSetState(ctx, step)
            "get_state" -> stepGetState(ctx, step)
            "remove_state" -> stepRemoveState(ctx, step)
            "clear_state" -> stepClearState(ctx, step)
            "increment_state", "inc_state" -> stepIncrementState(ctx, step)
            "append_state" -> stepAppendState(ctx, step)
            "emit_event" -> stepEmitEvent(ctx, step)
            else -> logW("[${ctx.pkg}] 未知 action 类型: $type")
        }
    }


    // ------------------------------------------------------------------------
    // 缺口 2: 条件检查 (Conditional Execution)
    // ------------------------------------------------------------------------
    fun evaluateCondition(ctx: ActionContext, condObj: Any?): Boolean {
        if (condObj == null) return true
        if (condObj is JSONArray) {
            for (i in 0 until condObj.length()) {
                if (!evaluateCondition(ctx, condObj.get(i))) return false
            }
            return true
        }
        val obj = condObj as? JSONObject ?: return true

        // 1. JS 脚本评估 condition
        if (obj.has("script") || obj.has("eval")) {
            val script = obj.optString("script", obj.optString("eval"))
            if (script.isNotEmpty()) {
                val res = evalJsInternal(ctx, script)
                return when (res) {
                    is Boolean -> res
                    is Number -> res.toDouble() != 0.0
                    is String -> res.isNotEmpty() && res != "false"
                    null -> false
                    else -> true
                }
            }
        }

        // 2. 表达式条件: { path, op, value }
        val pathExpr = obj.optString("path", obj.optString("target", obj.optString("var")))
        if (pathExpr.isEmpty()) return true

        val op = obj.optString("op", "eq").lowercase()
        val rawLeft = resolvePath(ctx, pathExpr)
        val leftVal = if (rawLeft === MISSING) null else rawLeft

        if (op == "is_null" || op == "null") return leftVal == null
        if (op == "not_null" || op == "non_null") return leftVal != null

        val rightVal = resolveValueItem(ctx, obj.opt("value"))

        val leftStr = leftVal?.toString() ?: ""
        val rightStr = rightVal?.toString() ?: ""

        return when (op) {
            "eq", "==", "equals" -> leftStr == rightStr
            "neq", "!=", "not_equals" -> leftStr != rightStr
            "contains" -> leftStr.contains(rightStr)
            "matches", "regex" -> try { Regex(rightStr).containsMatchIn(leftStr) } catch (_: Throwable) { false }
            "gt", ">" -> compareNums(leftVal, rightVal) > 0
            "gte", ">=" -> compareNums(leftVal, rightVal) >= 0
            "lt", "<" -> compareNums(leftVal, rightVal) < 0
            "lte", "<=" -> compareNums(leftVal, rightVal) <= 0
            else -> leftStr == rightStr
        }
    }

    private fun compareNums(a: Any?, b: Any?): Int {
        val da = (a as? Number)?.toDouble() ?: a.toString().toDoubleOrNull() ?: 0.0
        val db = (b as? Number)?.toDouble() ?: b.toString().toDoubleOrNull() ?: 0.0
        return da.compareTo(db)
    }

    // ------------------------------------------------------------------------
    // 缺口 1 & 3: 返回值 / 字段深层路径篡改 (Return Value & Field Mutation)
    // ------------------------------------------------------------------------
    private fun stepMutatePath(ctx: ActionContext, step: JSONObject) {
        val targetPath = step.optString("target", step.optString("path"))
        if (targetPath.isEmpty()) return
        val valObj = resolveValueItem(ctx, step.opt("value"))
        mutatePath(ctx, targetPath, valObj)
    }

    private fun applyMutateReturn(ctx: ActionContext, mutateList: JSONArray) {
        for (i in 0 until mutateList.length()) {
            val item = mutateList.optJSONObject(i) ?: continue
            val path = item.optString("path", item.optString("target"))
            if (path.isEmpty()) continue
            val fullPath = if (path.startsWith("ret.") || path.startsWith("result.") ||
                path.startsWith("args[") || path.startsWith("this.") || path.startsWith("$")) {
                path
            } else {
                "ret.$path"
            }
            val valObj = resolveValueItem(ctx, item.opt("value"))
            mutatePath(ctx, fullPath, valObj)
        }
    }

    fun mutatePath(ctx: ActionContext, pathExpr: String, newValue: Any?): Boolean {
        val expr = pathExpr.trim()
        if (expr.isEmpty()) return false

        if (expr.startsWith("state.")) {
            return ctx.runtimeState?.setPath(
                expr,
                newValue,
                ctx.hookId,
            ) == true
        }

        var lastDotOrBracket = -1
        var inQuote = false
        var quoteChar = ' '
        for (i in expr.indices) {
            val ch = expr[i]
            if ((ch == '\'' || ch == '"')) {
                if (!inQuote) { inQuote = true; quoteChar = ch }
                else if (quoteChar == ch) { inQuote = false }
            } else if (!inQuote && (ch == '.' || ch == '[')) {
                lastDotOrBracket = i
            }
        }

        if (lastDotOrBracket < 0) {
            if (expr == "ret" || expr == "result") {
                ctx.result = newValue
                return true
            }
            if (expr.startsWith("args[")) {
                val close = expr.indexOf(']')
                if (close > 0) {
                    val idx = expr.substring(5, close).toIntOrNull()
                    if (idx != null && ctx.args != null && idx in ctx.args!!.indices) {
                        ctx.args!![idx] = newValue
                        return true
                    }
                }
            }
            if (expr.startsWith("$")) {
                ctx.registers[expr] = newValue
                return true
            }
            return false
        }

        val parentExpr = expr.substring(0, lastDotOrBracket)
        val sep = expr[lastDotOrBracket]
        val parentObj = resolvePath(ctx, parentExpr)
        if (parentObj == null || parentObj === MISSING) {
            logW("无法篡改路径 '$expr': 父节点 '$parentExpr' 未能解析到有效对象")
            return false
        }


        val realParent = if (parentObj is TargetInstance) parentObj.instance else parentObj
        if (realParent == null) return false

        if (sep == '[') {
            val close = expr.indexOf(']', lastDotOrBracket)
            if (close < 0) return false
            val keyStr = expr.substring(lastDotOrBracket + 1, close).trim().removeSurrounding("'", "'").removeSurrounding("\"", "\"")
            val idx = keyStr.toIntOrNull()

            if (realParent is MutableMap<*, *>) {
                @Suppress("UNCHECKED_CAST")
                (realParent as MutableMap<Any?, Any?>)[keyStr] = newValue
                return true
            }
            if (idx != null && realParent is MutableList<*>) {
                @Suppress("UNCHECKED_CAST")
                (realParent as MutableList<Any?>)[idx] = newValue
                return true
            }
            if (idx != null && realParent.javaClass.isArray) {
                java.lang.reflect.Array.set(realParent, idx, newValue)
                return true
            }
            return setMemberField(realParent, keyStr, newValue)
        } else {
            val fieldName = expr.substring(lastDotOrBracket + 1).trim()
            if (realParent is MutableMap<*, *>) {
                @Suppress("UNCHECKED_CAST")
                (realParent as MutableMap<Any?, Any?>)[fieldName] = newValue
                return true
            }
            return setMemberField(realParent, fieldName, newValue)
        }
    }

    private fun setMemberField(obj: Any, fieldName: String, value: Any?): Boolean {
        var c: Class<*>? = obj.javaClass
        while (c != null) {
            try {
                val f = c.getDeclaredField(fieldName)
                f.isAccessible = true
                f.set(obj, value)
                return true
            } catch (_: NoSuchFieldException) {
                c = c.superclass
            } catch (t: Throwable) {
                logE("设置字段 $fieldName 失败 (${obj.javaClass.name}): $t")
                return false
            }

        }
        val cap = fieldName.replaceFirstChar { if (it.isLowerCase()) it.titlecase() else it.toString() }
        for (m in obj.javaClass.methods) {
            if (m.name == "set$cap" && m.parameterTypes.size == 1) {
                try {
                    m.isAccessible = true
                    m.invoke(obj, value)
                    return true
                } catch (_: Throwable) {}
            }
        }
        return false
    }

    // ------------------------------------------------------------------------
    // 缺口 4: 副作用调用 (Action Pipeline Implementation)
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

    private fun stepEvalJs(ctx: ActionContext, step: JSONObject) {
        val script = step.optString("script")
        if (script.isEmpty()) return
        val javaRes = evalJsInternal(ctx, script)

        val saveTo = step.optString("save_to")
        if (saveTo.isNotEmpty()) {
            ctx.registers[saveTo] = javaRes
        }
    }

    private fun evalJsInternal(ctx: ActionContext, script: String): Any? {
        val jsCtx = org.mozilla.javascript.Context.enter()
        try {
            jsCtx.optimizationLevel = -1 // Android 上关闭 JIT 字节码生成
            val scope: ScriptableObject = jsCtx.initStandardObjects()

            ScriptableObject.putProperty(scope, "\$this", org.mozilla.javascript.Context.javaToJS(ctx.thisObject, scope))
            ScriptableObject.putProperty(scope, "\$args", org.mozilla.javascript.Context.javaToJS(ctx.args, scope))
            ScriptableObject.putProperty(scope, "\$ret", org.mozilla.javascript.Context.javaToJS(ctx.result, scope))
            ScriptableObject.putProperty(scope, "\$ctx", org.mozilla.javascript.Context.javaToJS(ctx, scope))
            ScriptableObject.putProperty(scope, "\$regs", org.mozilla.javascript.Context.javaToJS(ctx.registers, scope))
            ScriptableObject.putProperty(
                scope,
                "\$state",
                org.mozilla.javascript.Context.javaToJS(
                    ctx.runtimeState?.view(ctx.hookId),
                    scope,
                ),
            )
            ScriptableObject.putProperty(
                scope,
                "\$stateStore",
                org.mozilla.javascript.Context.javaToJS(
                    ctx.runtimeState,
                    scope,
                ),
            )
            ScriptableObject.putProperty(
                scope,
                "\$event",
                org.mozilla.javascript.Context.javaToJS(
                    ctx.runtimeEvent?.asMap(),
                    scope,
                ),
            )
            ScriptableObject.putProperty(
                scope,
                "\$application",
                org.mozilla.javascript.Context.javaToJS(
                    ctx.contextRuntime?.applicationObject(),
                    scope,
                ),
            )
            ScriptableObject.putProperty(
                scope,
                "\$context",
                org.mozilla.javascript.Context.javaToJS(
                    ctx.contextRuntime?.contextObject(),
                    scope,
                ),
            )
            ScriptableObject.putProperty(
                scope,
                "\$activity",
                org.mozilla.javascript.Context.javaToJS(
                    ctx.contextRuntime?.activityObject(),
                    scope,
                ),
            )
            ScriptableObject.putProperty(
                scope,
                "\$lifecycle",
                org.mozilla.javascript.Context.javaToJS(
                    ctx.contextRuntime?.lifecycleView(),
                    scope,
                ),
            )

            val res = jsCtx.evaluateString(scope, script, "<m5_script>", 1, null)
            return when (res) {
                null, is org.mozilla.javascript.Undefined -> null
                is org.mozilla.javascript.Wrapper -> res.unwrap()
                else -> res
            }
        } finally {
            org.mozilla.javascript.Context.exit()
        }
    }

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

    private fun stepSetState(
        ctx: ActionContext,
        step: JSONObject,
    )
    {
        val state = ctx.runtimeState
            ?: throw IllegalStateException("Runtime State 未初始化")
        val scope = step.optString("scope", "process")
        val key = resolveValueItem(
            ctx,
            step.opt("key"),
        )?.toString()?.trim().orEmpty()
        if (key.isEmpty()) {
            throw IllegalArgumentException("set_state.key 不能为空")
        }

        val value = resolveStructuredValue(
            ctx,
            step.opt("value"),
        )
        state.set(scope, key, value, ctx.hookId)

        val saveTo = step.optString("save_to")
        if (saveTo.isNotEmpty()) {
            ctx.registers[saveTo] = value
        }
    }

    private fun stepGetState(
        ctx: ActionContext,
        step: JSONObject,
    )
    {
        val state = ctx.runtimeState
            ?: throw IllegalStateException("Runtime State 未初始化")
        val scope = step.optString("scope", "process")
        val key = resolveValueItem(
            ctx,
            step.opt("key"),
        )?.toString()?.trim().orEmpty()
        if (key.isEmpty()) {
            throw IllegalArgumentException("get_state.key 不能为空")
        }

        val value = state.get(scope, key, ctx.hookId)
        val saveTo = step.optString("save_to")
        if (saveTo.isNotEmpty()) {
            ctx.registers[saveTo] = value
        }
    }

    private fun stepRemoveState(
        ctx: ActionContext,
        step: JSONObject,
    )
    {
        val state = ctx.runtimeState
            ?: throw IllegalStateException("Runtime State 未初始化")
        val scope = step.optString("scope", "process")
        val key = resolveValueItem(
            ctx,
            step.opt("key"),
        )?.toString()?.trim().orEmpty()
        if (key.isEmpty()) {
            throw IllegalArgumentException("remove_state.key 不能为空")
        }

        val removed = state.remove(scope, key, ctx.hookId)
        val saveTo = step.optString("save_to")
        if (saveTo.isNotEmpty()) {
            ctx.registers[saveTo] = removed
        }
    }

    private fun stepClearState(
        ctx: ActionContext,
        step: JSONObject,
    )
    {
        val state = ctx.runtimeState
            ?: throw IllegalStateException("Runtime State 未初始化")
        val scope = step.optString("scope", "process")
        val count = state.clear(scope, ctx.hookId)

        val saveTo = step.optString("save_to")
        if (saveTo.isNotEmpty()) {
            ctx.registers[saveTo] = count
        }
    }

    private fun stepIncrementState(
        ctx: ActionContext,
        step: JSONObject,
    )
    {
        val state = ctx.runtimeState
            ?: throw IllegalStateException("Runtime State 未初始化")
        val scope = step.optString("scope", "process")
        val key = resolveValueItem(
            ctx,
            step.opt("key"),
        )?.toString()?.trim().orEmpty()
        if (key.isEmpty()) {
            throw IllegalArgumentException("increment_state.key 不能为空")
        }

        val rawDelta = resolveValueItem(
            ctx,
            if (step.has("delta")) {
                step.opt("delta")
            } else {
                1
            },
        )
        val delta = when (rawDelta) {
            is Number -> rawDelta.toDouble()
            else -> rawDelta?.toString()?.toDoubleOrNull() ?: 1.0
        }
        val value = state.increment(
            scope,
            key,
            delta,
            ctx.hookId,
        )

        val saveTo = step.optString("save_to")
        if (saveTo.isNotEmpty()) {
            ctx.registers[saveTo] = value
        }
    }

    private fun stepAppendState(
        ctx: ActionContext,
        step: JSONObject,
    )
    {
        val state = ctx.runtimeState
            ?: throw IllegalStateException("Runtime State 未初始化")
        val scope = step.optString("scope", "process")
        val key = resolveValueItem(
            ctx,
            step.opt("key"),
        )?.toString()?.trim().orEmpty()
        if (key.isEmpty()) {
            throw IllegalArgumentException("append_state.key 不能为空")
        }

        val value = resolveStructuredValue(
            ctx,
            step.opt("value"),
        )
        val list = state.append(
            scope,
            key,
            value,
            ctx.hookId,
        )

        val saveTo = step.optString("save_to")
        if (saveTo.isNotEmpty()) {
            ctx.registers[saveTo] = list
        }
    }

    private fun stepEmitEvent(
        ctx: ActionContext,
        step: JSONObject,
    )
    {
        val bus = ctx.eventBus
            ?: throw IllegalStateException("Runtime Event Bus 未初始化")
        val rawName = resolveValueItem(
            ctx,
            step.opt("name") ?: step.opt("event"),
        )
        val name = rawName?.toString()?.trim().orEmpty()
        if (name.isEmpty()) {
            throw IllegalArgumentException("emit_event.name 不能为空")
        }

        val payload = LinkedHashMap<String, Any?>()
        val rawPayload = step.optJSONObject("payload")
        if (rawPayload != null) {
            val iterator = rawPayload.keys()
            while (iterator.hasNext()) {
                val key = iterator.next()
                payload[key] = resolveStructuredValue(
                    ctx,
                    rawPayload.opt(key),
                )
            }
        }

        val delivered = bus.emit(
            RuntimeEvent(
                name = name,
                payload = payload,
                sourceHookId = ctx.hookId,
            )
        )
        val saveTo = step.optString("save_to")
        if (saveTo.isNotEmpty()) {
            ctx.registers[saveTo] = delivered
        }
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
    // 缺口 3 & 5: 通用表达式解析与模板变量 (Path Resolution & Template Variables)
    // ------------------------------------------------------------------------
    private class TargetClass(val clazz: Class<*>)
    private class TargetInstance(val instance: Any?)

    fun resolvePath(ctx: ActionContext, expr0: String): Any? {
        val expr = expr0.trim()
        if (expr.isEmpty()) return MISSING

        var cur: Any?
        var s: String

        when {
            expr == "application" ||
                expr.startsWith("application.") ||
                expr.startsWith("application[") -> {
                val runtime = ctx.contextRuntime ?: return MISSING
                cur = runtime.applicationObject() ?: return MISSING
                s = if (expr == "application") {
                    ""
                } else {
                    expr.substring("application".length)
                }
            }
            expr == "context" ||
                expr.startsWith("context.") ||
                expr.startsWith("context[") -> {
                val runtime = ctx.contextRuntime ?: return MISSING
                cur = runtime.contextObject() ?: return MISSING
                s = if (expr == "context") {
                    ""
                } else {
                    expr.substring("context".length)
                }
            }
            expr == "activity" ||
                expr.startsWith("activity.") ||
                expr.startsWith("activity[") -> {
                val runtime = ctx.contextRuntime ?: return MISSING
                cur = runtime.activityObject() ?: return MISSING
                s = if (expr == "activity") {
                    ""
                } else {
                    expr.substring("activity".length)
                }
            }
            expr == "lifecycle" ||
                expr.startsWith("lifecycle.") ||
                expr.startsWith("lifecycle[") -> {
                val runtime = ctx.contextRuntime ?: return MISSING
                cur = runtime.lifecycleView()
                s = if (expr == "lifecycle") {
                    ""
                } else {
                    expr.substring("lifecycle".length)
                }
            }
            expr.startsWith("state.") -> {
                val state = ctx.runtimeState ?: return MISSING
                return state.resolve(
                    expr,
                    ctx.hookId,
                )
            }
            expr == "event" ||
                expr.startsWith("event.") ||
                expr.startsWith("event[") -> {
                val eventMap = ctx.runtimeEvent?.asMap()
                    ?: return MISSING
                cur = eventMap
                s = if (expr == "event") {
                    ""
                } else {
                    expr.substring(5)
                }
            }
            expr == "this" || expr.startsWith("this.") || expr.startsWith("this[") -> {
                cur = ctx.thisObject
                s = if (expr == "this") "" else expr.substring(4)
            }
            expr == "ret" || expr == "result" || expr.startsWith("ret.") || expr.startsWith("ret[") || expr.startsWith("result.") || expr.startsWith("result[") -> {
                cur = ctx.result
                val prefixLen = if (expr.startsWith("result")) 6 else 3
                s = if (expr == "ret" || expr == "result") "" else expr.substring(prefixLen)
            }
            expr.startsWith("args[") -> {
                val close = expr.indexOf(']')
                if (close < 0) return MISSING
                val idx = expr.substring(5, close).toIntOrNull() ?: return MISSING
                val args = ctx.args
                if (args == null || idx !in args.indices) return MISSING
                cur = args[idx]
                s = expr.substring(close + 1)
            }
            expr.startsWith("class:") -> {
                val cName = expr.substring(6)
                return try { TargetClass(ctx.classLoader.loadClass(cName)) } catch (_: Throwable) { MISSING }
            }
            expr.startsWith("$") -> {
                val cut = expr.indexOfFirst { it == '.' || it == '[' }
                val regName = if (cut < 0) expr else expr.substring(0, cut)
                if (!ctx.registers.containsKey(regName)) return MISSING
                cur = ctx.registers[regName]
                s = if (cut < 0) "" else expr.substring(cut)
            }
            else -> {
                val cut = expr.indexOfFirst { it == '.' || it == '[' }
                val head = if (cut < 0) expr else expr.substring(0, cut)
                if (ctx.registers.containsKey(head) || ctx.registers.containsKey("$$head")) {
                    cur = ctx.registers[head] ?: ctx.registers["$$head"]
                    s = if (cut < 0) "" else expr.substring(cut)
                } else {
                    cur = ctx.thisObject
                    s = ".$expr"
                }
            }
        }

        while (s.isNotEmpty()) {
            if (cur == null) return MISSING
            if (s.startsWith(".")) {
                s = s.substring(1)
                continue
            }
            if (s.startsWith("[")) {
                val close = s.indexOf(']')
                if (close < 0) return MISSING
                val keyStr = s.substring(1, close).trim().removeSurrounding("'", "'").removeSurrounding("\"", "\"")
                val idx = keyStr.toIntOrNull()
                if (idx != null && (cur is List<*> || (cur != null && cur.javaClass.isArray))) {
                    cur = indexInto(cur, idx)
                } else if (cur is Map<*, *>) {
                    cur = mapGet(cur, keyStr)
                } else {
                    cur = memberOf(cur, keyStr)
                }
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

    private fun mapGet(map: Map<*, *>, keyStr: String): Any? {
        if (map.containsKey(keyStr)) return map[keyStr]
        val intKey = keyStr.toIntOrNull()
        if (intKey != null && map.containsKey(intKey)) return map[intKey]
        for ((k, v) in map) {
            if (k?.toString() == keyStr) return v
        }
        return MISSING
    }

    private fun memberOf(obj: Any, name: String): Any? {
        if (obj is TargetClass) return obj
        val inst = if (obj is TargetInstance) obj.instance else obj
        if (inst == null) return MISSING
        if (inst is Map<*, *>) {
            val res = mapGet(inst, name)
            if (res !== MISSING) return res
        }
        var c: Class<*>? = inst.javaClass
        while (c != null) {
            try {
                val f = c.getDeclaredField(name)
                f.isAccessible = true
                return f.get(inst)
            } catch (_: NoSuchFieldException) {
                c = c.superclass
            } catch (_: Throwable) {
                return MISSING
            }
        }
        val cap = name.replaceFirstChar { if (it.isLowerCase()) it.titlecase() else it.toString() }
        for (mName in listOf("get$cap", name, "is$cap")) {
            try {
                val m = inst.javaClass.getMethod(mName)
                m.isAccessible = true
                return m.invoke(inst)
            } catch (_: NoSuchMethodException) {
            } catch (_: Throwable) {
                return MISSING
            }
        }
        return MISSING
    }

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

    private fun resolveTarget(ctx: ActionContext, expr: String): Any? {
        val s = expr.trim()
        val res = resolvePath(ctx, s)
        if (res !== MISSING && res != null) return res
        if (s.startsWith("class:")) {
            val cName = s.substring(6)
            return try { TargetClass(ctx.classLoader.loadClass(cName)) } catch (_: Throwable) { null }
        }
        return ctx.registers[s] ?: ctx.thisObject
    }

    private fun resolveValueItem(ctx: ActionContext, vObj: Any?): Any? {
        if (vObj is JSONObject) {
            return resolveValue(ctx, vObj)
        }
        if (vObj is String) {
            val s = vObj.trim()
            // 单一模板表达式 "${ret.body.type}" -> 返回原始 Java 对象
            if (s.startsWith("\${") && s.endsWith("}") && countMatches(s, "\${") == 1) {
                val expr = s.substring(2, s.length - 1).trim()
                val resolved = resolvePath(ctx, expr)
                return if (resolved === MISSING) null else resolved
            }
            // 嵌入模板表达式 "Prefix_${args[0]}_Suffix" -> 插值拼接为字符串
            if (s.contains("\${")) {
                return interpolateTemplateString(ctx, vObj)
            }
            if (s.startsWith("$") && ctx.registers.containsKey(s)) {
                return ctx.registers[s]
            }
        }
        return vObj
    }

    private fun resolveStructuredValue(
        ctx: ActionContext,
        value: Any?,
    ): Any?
    {
        if (value == null || value === JSONObject.NULL) {
            return null
        }

        return when (value) {
            is JSONObject -> {
                if (isValueDescriptor(value)) {
                    resolveValue(ctx, value)
                } else {
                    val out = LinkedHashMap<String, Any?>()
                    val iterator = value.keys()
                    while (iterator.hasNext()) {
                        val key = iterator.next()
                        out[key] = resolveStructuredValue(
                            ctx,
                            value.opt(key),
                        )
                    }
                    out
                }
            }

            is JSONArray -> {
                val out = ArrayList<Any?>()
                for (index in 0 until value.length()) {
                    out.add(
                        resolveStructuredValue(
                            ctx,
                            value.opt(index),
                        )
                    )
                }
                out
            }

            else -> resolveValueItem(ctx, value)
        }
    }

    private fun isValueDescriptor(value: JSONObject): Boolean
    {
        if (value.has("path") || value.has("var")) {
            return true
        }
        if (!value.has("value")) {
            return false
        }

        val allowed = setOf("value", "type")
        val iterator = value.keys()
        while (iterator.hasNext()) {
            if (!allowed.contains(iterator.next())) {
                return false
            }
        }
        return true
    }

    private fun interpolateTemplateString(ctx: ActionContext, str: String): String {
        val sb = StringBuilder()
        var pos = 0
        while (pos < str.length) {
            val start = str.indexOf("\${", pos)
            if (start < 0) {
                sb.append(str.substring(pos))
                break
            }
            sb.append(str.substring(pos, start))
            val end = str.indexOf('}', start + 2)
            if (end < 0) {
                sb.append(str.substring(start))
                break
            }
            val expr = str.substring(start + 2, end).trim()
            val valObj = resolvePath(ctx, expr)
            val text = if (valObj === MISSING || valObj == null) "" else valObj.toString()
            sb.append(text)
            pos = end + 1
        }
        return sb.toString()
    }

    private fun countMatches(str: String, sub: String): Int {
        var count = 0
        var idx = 0
        while (str.indexOf(sub, idx).also { idx = it } != -1) {
            count++
            idx += sub.length
        }
        return count
    }

    private fun resolveValue(ctx: ActionContext, r: JSONObject): Any? {
        if (r.has("var")) {
            return ctx.registers[r.optString("var")]
        }
        if (r.has("path")) {
            val pVal = resolvePath(ctx, r.optString("path"))
            return if (pVal === MISSING) null else pVal
        }
        if (r.isNull("value")) return null
        val v = resolveValueItem(ctx, r.opt("value"))
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
