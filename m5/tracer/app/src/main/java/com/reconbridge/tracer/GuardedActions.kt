package com.reconbridge.tracer

import android.content.Context
import android.os.Build
import android.os.Handler
import android.os.Looper
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/** Reserve before side effects. Running Java calls cannot be forcibly undone. */
internal object GuardedActions {
    private val lock = Any()
    private val names = Regex("^[A-Za-z0-9_\\-\\u4e00-\\u9fff]{1,64}$")
    private fun key(task: String) = "action_guard.$task"
    private fun app(ctx: ActionContext): Context? =
        (ctx.contextRuntime?.applicationObject() ?: ctx.contextRuntime?.contextObject()) as? Context

    private fun load(ctx: ActionContext, task: String): JSONObject {
        val text = app(ctx)?.getSharedPreferences("reconbridge_action_guards", Context.MODE_PRIVATE)
            ?.getString(key(task), null)
        if (text != null) return JSONObject(text)
        val value = ctx.runtimeState?.get("process", key(task))
        return if (value is Map<*, *>) JSONObject(value) else JSONObject()
    }

    private fun map(obj: JSONObject): Map<String, Any?> {
        val out = linkedMapOf<String, Any?>()
        for (k in obj.keys()) {
            out[k] = when (val v = obj.opt(k)) {
                JSONObject.NULL -> null
                is JSONObject -> map(v)
                is JSONArray -> (0 until v.length()).map { v.opt(it) }
                else -> v
            }
        }
        return out
    }

    private fun store(ctx: ActionContext, task: String, state: JSONObject) {
        val app = app(ctx)
        if (app != null) check(app.getSharedPreferences("reconbridge_action_guards", Context.MODE_PRIVATE)
            .edit().putString(key(task), state.toString()).commit()) { "cannot persist action reservation" }
        ctx.runtimeState?.set("process", key(task), map(state))
    }

    private fun report(ctx: ActionContext, state: JSONObject) { ctx.registers["\$guard_result"] = map(state) }
    private fun string(ctx: ActionContext, step: JSONObject, field: String): String {
        val value = ActionExecutor.resolveActionValue(ctx, step.opt(field))
        require(value != null && value !== ActionExecutor.MISSING) { "$field required" }
        return value.toString()
    }

    fun execute(ctx: ActionContext, step: JSONObject, runner: (JSONArray, Long) -> Unit) {
        check(ctx.runtimeState != null) { "Runtime State required for guarded actions" }
        val task = string(ctx, step, "task_id")
        val run = string(ctx, step, "run_id")
        val businessKey = string(ctx, step, "dedup_key")
        require(names.matches(task) && run.isNotBlank() && run.length <= 128 && businessKey.isNotBlank() && businessKey.length <= 256)
        val maxRuns = step.optInt("max_runs", 10)
        val interval = step.optLong("min_interval_ms", 1000)
        val timeout = step.optLong("timeout_ms", 5000)
        require(maxRuns in 1..1000 && interval in 0..3600000 && timeout in 200..10000)
        val actions = step.getJSONArray("actions")
        require(actions.length() in 1..32)
        step.optJSONObject("input_schema")?.let { schema ->
            val inputs = ctx.runtimeEvent?.payload?.get("inputs") as? Map<*, *>
                ?: throw IllegalArgumentException("event.inputs required")
            require(inputs.keys == schema.keys().asSequence().toSet())
            for (name in schema.keys()) {
                val type = schema.getJSONObject(name).getString("type")
                val value = inputs[name]
                val valid = if (value == null && type.startsWith("java.lang.")) true else when (type) {
                    "boolean", "java.lang.Boolean" -> value is Boolean
                    "java.lang.String" -> value is String
                    "char" -> value is String && value.length == 1
                    "byte", "java.lang.Byte" -> value is Number && value.toDouble() == value.toLong().toDouble() && value.toLong() in -128..127
                    "short", "java.lang.Short" -> value is Number && value.toDouble() == value.toLong().toDouble() && value.toLong() in -32768..32767
                    "int", "java.lang.Integer" -> value is Number && value.toDouble() == value.toLong().toDouble() && value.toLong() in Int.MIN_VALUE.toLong()..Int.MAX_VALUE.toLong()
                    "long", "java.lang.Long" -> value is Byte || value is Short || value is Int || value is Long
                    "float", "double", "java.lang.Float", "java.lang.Double" -> value is Number && value.toDouble().isFinite()
                    else -> false
                }
                require(valid) { "invalid input $name ($type)" }
            }
        }
        if (step.has("expected_version_code")) {
            val context = app(ctx) ?: throw IllegalStateException("Context required for version check")
            @Suppress("DEPRECATION") val info = context.packageManager.getPackageInfo(ctx.pkg, 0)
            @Suppress("DEPRECATION") val actual = if (Build.VERSION.SDK_INT >= 28) info.longVersionCode else info.versionCode.toLong()
            require(actual.toString() == step.getString("expected_version_code")) { "application version changed" }
        }
        val state: JSONObject
        synchronized(lock) {
            state = load(ctx, task)
            val status = state.optString("status")
            val seen = state.optJSONArray("dedup_keys") ?: JSONArray()
            val count = state.optInt("count", 0)
            val reason = when {
                status.isNotEmpty() && status != "verified" -> "previous run pending/failed/uncertain"
                count >= maxRuns -> "run limit reached"
                (0 until seen.length()).any { seen.optString(it) == businessKey } -> "duplicate business item"
                state.has("last_started_at") && System.currentTimeMillis() - state.optLong("last_started_at") < interval -> "minimum interval not reached"
                else -> ""
            }
            if (reason.isNotEmpty()) {
                report(ctx, JSONObject().put("status", "blocked").put("reason", reason).put("run_id", run))
                return
            }
            state.put("status", "in_progress").put("run_id", run).put("count", count + 1)
                .put("last_started_at", System.currentTimeMillis()).put("dedup_keys", seen.put(businessKey))
            store(ctx, task, state)
        }
        val deadline = System.nanoTime() + timeout * 1000000
        try {
            dispatch(ctx, step.optBoolean("dispatch_main_thread", false), timeout) { runner(actions, deadline) }
            check(System.nanoTime() <= deadline) { "deadline exceeded; running calls may have completed" }
            state.put("status", "awaiting_verification")
        } catch (t: Throwable) { state.put("status", "uncertain").put("error", t.toString()) }
        synchronized(lock) { store(ctx, task, state) }
        report(ctx, state)
    }

    private fun dispatch(ctx: ActionContext, main: Boolean, timeout: Long, work: () -> Unit) {
        if (!main || Looper.myLooper() == Looper.getMainLooper()) { work(); return }
        check(ctx.contextRuntime?.activityObject() != null) { "no current Activity" }
        val handler = Handler(Looper.getMainLooper())
        val done = CountDownLatch(1)
        val cancelled = AtomicBoolean(false)
        var error: Throwable? = null
        val runnable = Runnable {
            try { if (!cancelled.get()) work() } catch (t: Throwable) { error = t } finally { done.countDown() }
        }
        check(handler.post(runnable))
        if (!done.await(timeout, TimeUnit.MILLISECONDS)) {
            cancelled.set(true); handler.removeCallbacks(runnable)
            throw IllegalStateException("main thread timed out; in-flight actions cannot be cancelled")
        }
        error?.let { throw it }
    }

    fun complete(ctx: ActionContext, step: JSONObject) {
        val task = string(ctx, step, "task_id")
        val run = string(ctx, step, "run_id")
        require(names.matches(task))
        synchronized(lock) {
            val state = load(ctx, task)
            require(state.optString("run_id") == run && state.optString("status") == "awaiting_verification") {
                "completion must match the pending run_id"
            }
            val verified = ActionExecutor.resolveActionValue(ctx, step.opt("verified"))
            require(verified is Boolean)
            state.put("status", if (verified) "verified" else "uncertain").put("finished_at", System.currentTimeMillis())
            store(ctx, task, state); report(ctx, state)
        }
    }
}
