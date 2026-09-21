package com.reconbridge.tracer

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

private class FakeRuntimeContext(
    private val activity: Any? = null,
) : RuntimeContextProvider
{
    override fun applicationObject(): Any?
    {
        return "fake-application"
    }

    override fun contextObject(): Any?
    {
        return activity ?: "fake-context"
    }

    override fun activityObject(): Any?
    {
        return activity
    }

    override fun lifecycleView(): Map<String, Any?>
    {
        return linkedMapOf(
            "activity_class" to activity?.javaClass?.name,
            "activity_state" to if (activity != null) "resumed" else "",
            "has_activity" to (activity != null),
        )
    }

    override fun snapshotJson(): JSONObject
    {
        return JSONObject().apply {
            put("enabled", true)
            put("activity_available", activity != null)
            put(
                "activity_class",
                activity?.javaClass?.name ?: JSONObject.NULL,
            )
        }
    }
}

private class FakeActivityActionTarget
{
    var hits = 0

    fun ping(): String
    {
        hits++
        return "pong-" + hits
    }
}

class RuntimeCommandDispatcherTest
{
    private fun dispatcher(
        state: RuntimeStateStore = RuntimeStateStore("com.test.pkg"),
        bus: RuntimeEventBus = RuntimeEventBus(),
        context: RuntimeContextProvider = FakeRuntimeContext(),
    ): RuntimeCommandDispatcher
    {
        return RuntimeCommandDispatcher(
            packageName = "com.test.pkg",
            classLoader = RuntimeCommandDispatcherTest::class.java.classLoader!!,
            runtimeState = state,
            eventBus = bus,
            contextRuntime = context,
        )
    }

    private fun execute(
        dispatcher: RuntimeCommandDispatcher,
        requestId: String,
        op: String,
        configure: JSONObject.() -> Unit = {},
    ): JSONObject
    {
        val command = JSONObject()
            .put("request_id", requestId)
            .put("op", op)
            .apply(configure)
        return JSONObject(
            dispatcher.execute(command.toString())
        )
    }

    @Test
    fun stateSetGetRoundTripsNestedJsonAndNull()
    {
        val dispatcher = dispatcher()

        val set = execute(
            dispatcher,
            "r1",
            "state_set",
        ) {
            put("scope", "process")
            put("key", "profile")
            put(
                "value",
                JSONObject()
                    .put("vip", true)
                    .put(
                        "roles",
                        JSONArray().put("user").put("tester"),
                    )
                    .put("note", JSONObject.NULL),
            )
        }

        assertTrue(set.getBoolean("ok"))
        assertEquals("r1", set.getString("request_id"))

        val get = execute(
            dispatcher,
            "r2",
            "state_get",
        ) {
            put("scope", "process")
            put("key", "profile")
        }

        assertTrue(get.getBoolean("ok"))
        val result = get.getJSONObject("result")
        assertTrue(result.getBoolean("exists"))
        val value = result.getJSONObject("value")
        assertTrue(value.getBoolean("vip"))
        assertEquals(
            "tester",
            value.getJSONArray("roles").getString(1),
        )
        assertTrue(value.isNull("note"))

        execute(
            dispatcher,
            "r3",
            "state_set",
        ) {
            put("key", "nullable")
            put("value", JSONObject.NULL)
        }
        val nullable = execute(
            dispatcher,
            "r4",
            "state_get",
        ) {
            put("key", "nullable")
        }.getJSONObject("result")
        assertTrue(nullable.getBoolean("exists"))
        assertTrue(nullable.isNull("value"))
    }

    @Test
    fun remoteThreadScopeIsRejected()
    {
        val result = execute(
            dispatcher(),
            "thread-1",
            "state_get",
        ) {
            put("scope", "thread")
            put("key", "request")
        }

        assertFalse(result.getBoolean("ok"))
        assertEquals("thread-1", result.getString("request_id"))
        assertTrue(
            result.getString("error").contains("ThreadLocal")
        )
    }

    @Test
    fun remoteEventCanDriveExistingListenerAndSharedState()
    {
        val state = RuntimeStateStore("com.test.pkg")
        val bus = RuntimeEventBus()
        bus.subscribe(
            ownerHookId = "listener",
            eventName = "remote.vip",
        ) { event ->
            state.set(
                "process",
                "vip",
                event.payload["vip"],
                "listener",
            )
        }
        val dispatcher = dispatcher(
            state = state,
            bus = bus,
        )

        val emitted = execute(
            dispatcher,
            "event-1",
            "event_emit",
        ) {
            put("name", "remote.vip")
            put(
                "payload",
                JSONObject().put("vip", true),
            )
        }

        assertTrue(emitted.getBoolean("ok"))
        assertEquals(
            1,
            emitted.getJSONObject("result")
                .getInt("listener_count"),
        )
        assertEquals(
            true,
            state.get(
                "process",
                "vip",
                "listener",
            ),
        )
    }

    @Test
    fun contextStatusReturnsCurrentRuntimeView()
    {
        val activity = FakeActivityActionTarget()
        val result = execute(
            dispatcher(
                context = FakeRuntimeContext(activity),
            ),
            "ctx-1",
            "context_status",
        )

        assertTrue(result.getBoolean("ok"))
        val value = result.getJSONObject("result")
        assertEquals(
            "com.test.pkg",
            value.getString("package"),
        )
        assertTrue(
            value.getJSONObject("context_runtime")
                .getBoolean("activity_available"),
        )
        assertTrue(
            value.getJSONObject("lifecycle")
                .getBoolean("has_activity"),
        )
    }

    @Test
    fun activityActionReusesActionPipelineAndReturnsRegisters()
    {
        val activity = FakeActivityActionTarget()
        val result = execute(
            dispatcher(
                context = FakeRuntimeContext(activity),
            ),
            "act-1",
            "activity_action",
        ) {
            put(
                "actions",
                JSONArray().put(
                    JSONObject()
                        .put("action", "call_method")
                        .put("target", "activity")
                        .put("method", "ping")
                        .put("save_to", "$reply")
                ),
            )
        }

        assertTrue(result.getBoolean("ok"))
        val value = result.getJSONObject("result")
        assertEquals(1, activity.hits)
        assertEquals(
            "pong-1",
            value.getJSONObject("registers")
                .getString("$reply"),
        )
    }

    @Test
    fun activityActionFailsClearlyWithoutCurrentActivity()
    {
        val result = execute(
            dispatcher(),
            "act-2",
            "activity_action",
        ) {
            put(
                "actions",
                JSONArray().put(
                    JSONObject().put(
                        "action",
                        "set_state",
                    )
                ),
            )
        }

        assertFalse(result.getBoolean("ok"))
        assertTrue(
            result.getString("error").contains("Activity")
        )
    }
}
