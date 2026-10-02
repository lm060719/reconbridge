package com.reconbridge.tracer

import android.app.Activity
import android.os.Handler
import android.os.Looper
import org.json.JSONArray
import org.json.JSONObject
import java.util.LinkedHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

/**
 * Runtime Phase 5：处理 daemon 从现有注入 socket 直接下发的交互命令。
 *
 * 这条路径不修改 Hook 配置，也不创建临时 Java Hook。所有命令仍运行在目标 App 进程内，
 * 并复用 RuntimeStateStore / RuntimeEventBus / ContextRegistry / ActionExecutor。
 */
internal class RuntimeCommandDispatcher(
    private val packageName: String,
    private val classLoader: ClassLoader,
    private val runtimeState: RuntimeStateStore,
    private val eventBus: RuntimeEventBus,
    private val contextRuntime: RuntimeContextProvider,
)
{
    fun execute(commandText: String): String
    {
        val command = try {
            JSONObject(commandText)
        } catch (t: Throwable) {
            return errorResponse(
                requestId = "",
                op = "",
                message = "Runtime command JSON 解析失败: " + t,
            ).toString()
        }

        val requestId = command.optString("request_id", "")
        val op = command.optString("op", "").trim().lowercase()
        if (requestId.isEmpty()) {
            return errorResponse(
                requestId = "",
                op = op,
                message = "request_id 不能为空",
            ).toString()
        }
        if (op.isEmpty()) {
            return errorResponse(
                requestId = requestId,
                op = "",
                message = "op 不能为空",
            ).toString()
        }

        return try {
            val result = when (op) {
                "state_get" -> stateGet(command)
                "state_set" -> stateSet(command)
                "state_remove" -> stateRemove(command)
                "state_clear" -> stateClear(command)
                "state_increment" -> stateIncrement(command)
                "state_append" -> stateAppend(command)
                "event_emit" -> eventEmit(command)
                "context_status" -> contextStatus()
                "activity_action" -> activityAction(command)
                else -> throw IllegalArgumentException(
                    "不支持的 Runtime command: " + op
                )
            }

            JSONObject().apply {
                put("request_id", requestId)
                put("ok", true)
                put("op", op)
                put("result", result)
            }.toString()
        } catch (t: Throwable) {
            errorResponse(
                requestId = requestId,
                op = op,
                message = t.toString(),
            ).toString()
        }
    }

    private fun stateGet(command: JSONObject): JSONObject
    {
        val scope = remoteScope(command)
        val key = requiredKey(command)
        val hookId = hookId(command, scope)
        val exists = runtimeState.contains(scope, key, hookId)
        val value = if (exists) {
            runtimeState.get(scope, key, hookId)
        } else {
            null
        }

        return JSONObject().apply {
            put("scope", scope)
            put("key", key)
            if (hookId.isNotEmpty()) {
                put("hook_id", hookId)
            }
            put("exists", exists)
            put("value", toJsonSafe(value))
        }
    }

    private fun stateSet(command: JSONObject): JSONObject
    {
        val scope = remoteScope(command)
        val key = requiredKey(command)
        val hookId = hookId(command, scope)
        val value = jsonToRuntimeValue(command.opt("value"))

        runtimeState.set(
            scope = scope,
            key = key,
            value = value,
            hookId = hookId,
        )

        return JSONObject().apply {
            put("scope", scope)
            put("key", key)
            if (hookId.isNotEmpty()) {
                put("hook_id", hookId)
            }
            put("value", toJsonSafe(value))
        }
    }

    private fun stateRemove(command: JSONObject): JSONObject
    {
        val scope = remoteScope(command)
        val key = requiredKey(command)
        val hookId = hookId(command, scope)
        val existed = runtimeState.contains(scope, key, hookId)
        val old = runtimeState.remove(scope, key, hookId)

        return JSONObject().apply {
            put("scope", scope)
            put("key", key)
            if (hookId.isNotEmpty()) {
                put("hook_id", hookId)
            }
            put("removed", existed)
            put("old_value", toJsonSafe(old))
        }
    }

    private fun stateClear(command: JSONObject): JSONObject
    {
        val scope = remoteScope(command)
        val hookId = hookId(command, scope)
        val cleared = runtimeState.clear(scope, hookId)

        return JSONObject().apply {
            put("scope", scope)
            if (hookId.isNotEmpty()) {
                put("hook_id", hookId)
            }
            put("cleared", cleared)
        }
    }

    private fun stateIncrement(command: JSONObject): JSONObject
    {
        val scope = remoteScope(command)
        val key = requiredKey(command)
        val hookId = hookId(command, scope)
        val delta = command.optDouble("delta", 1.0)
        val value = runtimeState.increment(
            scope = scope,
            key = key,
            delta = delta,
            hookId = hookId,
        )

        return JSONObject().apply {
            put("scope", scope)
            put("key", key)
            if (hookId.isNotEmpty()) {
                put("hook_id", hookId)
            }
            put("value", value)
        }
    }

    private fun stateAppend(command: JSONObject): JSONObject
    {
        val scope = remoteScope(command)
        val key = requiredKey(command)
        val hookId = hookId(command, scope)
        val value = jsonToRuntimeValue(command.opt("value"))
        val list = runtimeState.append(
            scope = scope,
            key = key,
            value = value,
            hookId = hookId,
        )

        return JSONObject().apply {
            put("scope", scope)
            put("key", key)
            if (hookId.isNotEmpty()) {
                put("hook_id", hookId)
            }
            put("value", toJsonSafe(list))
        }
    }

    private fun eventEmit(command: JSONObject): JSONObject
    {
        val name = command.optString("name", "").trim()
        require(name.isNotEmpty()) {
            "event name 不能为空"
        }

        val payload = when (val raw = command.opt("payload")) {
            null,
            JSONObject.NULL -> emptyMap()

            is JSONObject -> {
                @Suppress("UNCHECKED_CAST")
                jsonToRuntimeValue(raw) as Map<String, Any?>
            }

            else -> throw IllegalArgumentException(
                "event payload 必须是 JSON object"
            )
        }
        val source = command.optString(
            "source_hook",
            "__remote__",
        ).ifEmpty {
            "__remote__"
        }

        val delivered = eventBus.emit(
            RuntimeEvent(
                name = name,
                payload = payload,
                sourceHookId = source,
            )
        )

        return JSONObject().apply {
            put("name", name)
            put("source_hook", source)
            put("listener_count", delivered)
            put("payload", toJsonSafe(payload))
        }
    }

    private fun contextStatus(): JSONObject
    {
        return JSONObject().apply {
            put("package", packageName)
            put("context_runtime", contextRuntime.snapshotJson())
            put(
                "lifecycle",
                toJsonSafe(contextRuntime.lifecycleView()),
            )
        }
    }

    private fun activityAction(command: JSONObject): JSONObject
    {
        val activity = contextRuntime.activityObject()
            ?: throw IllegalStateException(
                "当前没有可用 Activity"
            )
        val actions = command.optJSONArray("actions")
            ?: throw IllegalArgumentException(
                "activity_action.actions 必须是数组"
            )

        val execute = {
            executeActivityActions(
                activity,
                actions,
            )
        }

        return if (activity is Activity) {
            runActivityActionOnMainThread(
                activity,
                command,
                execute,
            )
        } else {
            // JVM 单元测试 / fake RuntimeContextProvider 不依赖 Android Looper。
            execute()
        }
    }

    private fun executeActivityActions(
        activity: Any,
        actions: JSONArray,
    ): JSONObject
    {
        val ctx = ActionContext(
            param = null,
            classLoader = classLoader,
            pkg = packageName,
            hookId = "__remote_activity__",
            runtimeState = runtimeState,
            eventBus = eventBus,
            contextRuntime = contextRuntime,
        )
        ctx.thisObject = activity

        val wrapper = JSONObject().put(
            "before_actions",
            JSONArray(actions.toString()),
        )
        ActionExecutor.executeActions(
            ctx,
            wrapper,
            "before",
        )

        val registers = JSONObject()
        for ((key, value) in ctx.registers) {
            registers.put(
                key,
                toJsonSafe(value),
            )
        }

        return JSONObject().apply {
            put("activity_class", activity.javaClass.name)
            put("executed", actions.length())
            put("main_thread", activity is Activity)
            put("registers", registers)
        }
    }

    private fun runActivityActionOnMainThread(
        activity: Activity,
        command: JSONObject,
        block: () -> JSONObject,
    ): JSONObject
    {
        if (Looper.myLooper() == Looper.getMainLooper()) {
            return block()
        }

        val timeoutMs = command.optLong(
            "_timeout_ms",
            3000L,
        ).coerceIn(200L, 10000L)
        val waitMs = (timeoutMs - 150L).coerceAtLeast(100L)
        val handler = Handler(Looper.getMainLooper())
        val latch = CountDownLatch(1)
        val cancelled = AtomicBoolean(false)
        val result = AtomicReference<JSONObject?>()
        val error = AtomicReference<Throwable?>()

        val runnable = Runnable {
            try {
                if (!cancelled.get()) {
                    result.set(block())
                }
            } catch (t: Throwable) {
                error.set(t)
            } finally {
                latch.countDown()
            }
        }

        if (!handler.post(runnable)) {
            throw IllegalStateException(
                "无法把 Activity Action 调度到主线程"
            )
        }

        if (!latch.await(waitMs, TimeUnit.MILLISECONDS)) {
            cancelled.set(true)
            handler.removeCallbacks(runnable)
            throw IllegalStateException(
                "Activity Action 主线程执行超时"
            )
        }

        error.get()?.let {
            throw it
        }
        return result.get()
            ?: throw IllegalStateException(
                "Activity Action 未返回结果"
            )
    }

    private fun remoteScope(command: JSONObject): String
    {
        val raw = command.optString("scope", "process")
            .trim()
            .lowercase()
        val scope = when (raw) {
            "",
            "global" -> "process"

            "pkg" -> "package"
            else -> raw
        }

        require(
            scope == "process" ||
                scope == "package" ||
                scope == "hook"
        ) {
            if (scope == "thread") {
                "远程 Runtime command 不支持 thread scope；ThreadLocal 属于命令线程，无法代表 Hook 线程"
            } else {
                "无效 state scope: " + scope
            }
        }
        return scope
    }

    private fun requiredKey(command: JSONObject): String
    {
        val key = command.optString("key", "").trim()
        require(key.isNotEmpty()) {
            "state key 不能为空"
        }
        return key
    }

    private fun hookId(
        command: JSONObject,
        scope: String,
    ): String
    {
        if (scope != "hook") {
            return ""
        }
        val hookId = command.optString("hook_id", "").trim()
        require(hookId.isNotEmpty()) {
            "hook scope 必须提供 hook_id"
        }
        return hookId
    }

    private fun errorResponse(
        requestId: String,
        op: String,
        message: String,
    ): JSONObject
    {
        return JSONObject().apply {
            put("request_id", requestId)
            put("ok", false)
            put("op", op)
            put("error", message)
        }
    }

    companion object
    {
        internal fun jsonToRuntimeValue(value: Any?): Any?
        {
            if (value == null || value === JSONObject.NULL) {
                return null
            }
            return when (value) {
                is JSONObject -> {
                    val map = LinkedHashMap<String, Any?>()
                    val keys = value.keys()
                    while (keys.hasNext()) {
                        val key = keys.next()
                        map[key] = jsonToRuntimeValue(
                            value.opt(key)
                        )
                    }
                    map
                }

                is JSONArray -> {
                    val list = ArrayList<Any?>()
                    for (index in 0 until value.length()) {
                        list.add(
                            jsonToRuntimeValue(
                                value.opt(index)
                            )
                        )
                    }
                    list
                }

                else -> value
            }
        }

        internal fun toJsonSafe(value: Any?): Any
        {
            if (value == null) {
                return JSONObject.NULL
            }
            return when (value) {
                is Boolean,
                is Number,
                is String -> value

                is CharSequence -> value.toString()

                is Map<*, *> -> {
                    JSONObject().apply {
                        var count = 0
                        for ((key, item) in value) {
                            if (count >= 128) {
                                put("_truncated", true)
                                break
                            }
                            put(
                                key?.toString() ?: "null",
                                toJsonSafe(item),
                            )
                            count++
                        }
                    }
                }

                is Collection<*> -> {
                    JSONArray().apply {
                        for (item in value.take(128)) {
                            put(toJsonSafe(item))
                        }
                    }
                }

                is Array<*> -> {
                    JSONArray().apply {
                        for (item in value.take(128)) {
                            put(toJsonSafe(item))
                        }
                    }
                }

                else -> {
                    JSONObject().apply {
                        put("type", value.javaClass.name)
                        val text = try {
                            value.toString()
                        } catch (_: Throwable) {
                            "<toString failed>"
                        }
                        put(
                            "preview",
                            if (text.length <= 512) {
                                text
                            } else {
                                text.substring(0, 512) + "…"
                            },
                        )
                    }
                }
            }
        }
    }
}
