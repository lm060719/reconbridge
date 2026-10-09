package com.reconbridge.tracer

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class GuardTarget {
    var calls = 0
    fun ping(): String { calls++; return "ok" }
    fun fail() { throw IllegalStateException("business failure") }
    fun slow() { calls++; Thread.sleep(230) }
    fun accept(id: Long, text: String): String = "$id:$text"
}

class GuardedActionsTest {
    private fun context(state: RuntimeStateStore, target: GuardTarget = GuardTarget()): ActionContext =
        ActionContext(null, javaClass.classLoader!!, "com.test.app", runtimeState = state).also { it.thisObject = target }

    private fun call(method: String): JSONObject = JSONObject().put("action", "call_method")
        .put("target", "this").put("method", method)

    private fun guard(run: String = "r1", key: String = "item:1", max: Int = 10,
                      actions: JSONArray = JSONArray().put(call("ping")), timeout: Int = 5000): JSONObject =
        JSONObject().put("action", "run_guarded").put("task_id", "task").put("run_id", run)
            .put("dedup_key", key).put("min_interval_ms", 0).put("max_runs", max)
            .put("timeout_ms", timeout).put("actions", actions)

    private fun execute(ctx: ActionContext, step: JSONObject) {
        ActionExecutor.executeActions(ctx, JSONObject().put("before_actions", JSONArray().put(step)), "before")
    }

    private fun result(ctx: ActionContext): Map<*, *> = ctx.registers["\$guard_result"] as Map<*, *>
    private fun complete(ctx: ActionContext, run: String = "r1", success: Boolean = true) {
        execute(ctx, JSONObject().put("action", "complete_guarded").put("task_id", "task")
            .put("run_id", run).put("verified", success))
    }

    @Test fun successfulInvocationStillRequiresIndependentVerification() {
        val state = RuntimeStateStore("com.test.app")
        val target = GuardTarget()
        val ctx = context(state, target)
        execute(ctx, guard())
        assertEquals(1, target.calls)
        assertEquals("awaiting_verification", result(ctx)["status"])
        val next = context(state, target)
        execute(next, guard("r2", "item:2"))
        assertEquals("blocked", result(next)["status"])
        assertEquals(1, target.calls)
        complete(ctx)
        assertEquals("verified", result(ctx)["status"])
    }

    @Test fun verifiedBusinessKeyCannotBeSubmittedAgain() {
        val state = RuntimeStateStore("com.test.app")
        val target = GuardTarget()
        val ctx = context(state, target)
        execute(ctx, guard()); complete(ctx)
        execute(ctx, guard("r2"))
        assertEquals("blocked", result(ctx)["status"])
        assertEquals("duplicate business item", result(ctx)["reason"])
        assertEquals(1, target.calls)
    }

    @Test fun maximumRunsIsEnforcedAfterVerification() {
        val ctx = context(RuntimeStateStore("com.test.app"))
        execute(ctx, guard(max = 1)); complete(ctx)
        execute(ctx, guard("r2", "item:2", max = 1))
        assertEquals("run limit reached", result(ctx)["reason"])
    }

    @Test fun businessExceptionStopsLaterStepsAndHaltsTask() {
        val target = GuardTarget()
        val ctx = context(RuntimeStateStore("com.test.app"), target)
        execute(ctx, guard(actions = JSONArray().put(call("fail")).put(call("ping"))))
        assertEquals(0, target.calls)
        assertEquals("uncertain", result(ctx)["status"])
        assertFalse(ctx.actionErrors.isEmpty())
        execute(ctx, guard("r2", "item:2"))
        assertEquals("blocked", result(ctx)["status"])
    }

    @Test fun cooperativeDeadlineDoesNotClaimCancellationOfRunningMethod() {
        val target = GuardTarget()
        val ctx = context(RuntimeStateStore("com.test.app"), target)
        execute(ctx, guard(actions = JSONArray().put(call("slow")).put(call("ping")), timeout = 200))
        assertEquals(1, target.calls)
        assertEquals("uncertain", result(ctx)["status"])
    }

    @Test fun completionCannotAcknowledgeADifferentRun() {
        val ctx = context(RuntimeStateStore("com.test.app"))
        execute(ctx, guard())
        complete(ctx, run = "other")
        assertFalse(ctx.actionErrors.isEmpty())
        val state = ctx.runtimeState!!.get("process", "action_guard.task") as Map<*, *>
        assertEquals("awaiting_verification", state["status"])
    }

    @Test fun failedVerificationBlocksLaterCalls() {
        val ctx = context(RuntimeStateStore("com.test.app"))
        execute(ctx, guard()); complete(ctx, success = false)
        assertEquals("uncertain", result(ctx)["status"])
        execute(ctx, guard("r2", "item:2"))
        assertEquals("blocked", result(ctx)["status"])
    }

    @Test fun literalDescriptorsPreserveTemplateLookingDataAndExactLongArguments() {
        val ctx = context(RuntimeStateStore("com.test.app"))
        val step = call("accept").put("params", JSONArray().put("long").put("java.lang.String"))
            .put("args", JSONArray().put(JSONObject().put("literal", 4))
                .put(JSONObject().put("literal", "\${state.process.secret}")))
            .put("save_to", "\$reply")
        execute(ctx, step)
        assertTrue(ctx.actionErrors.isEmpty())
        assertEquals("4:\${state.process.secret}", ctx.registers["\$reply"])
    }

    @Test fun unknownActionIsReportedRatherThanCountedAsSuccess() {
        val ctx = context(RuntimeStateStore("com.test.app"))
        execute(ctx, JSONObject().put("action", "missing_action"))
        assertEquals(1, ctx.actionErrors.size)
    }

    @Test fun wrongReceiverCannotCallASameNamedMethod() {
        val target = GuardTarget()
        val ctx = context(RuntimeStateStore("com.test.app"), target)
        execute(ctx, call("ping").put("expected_class", "java.lang.String"))
        assertEquals(0, target.calls)
        assertEquals(1, ctx.actionErrors.size)
    }
}
