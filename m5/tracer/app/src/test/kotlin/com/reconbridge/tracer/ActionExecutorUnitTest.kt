package com.reconbridge.tracer

import de.robv.android.xposed.XC_MethodHook.MethodHookParam
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SampleHolder
{
    var title: String = "default_title"
    val info: MutableMap<String, Any> = mutableMapOf(
        "status" to "ok",
        "code" to 200,
    )
}

class ActionExecutorUnitTest
{
    private fun createParam(
        thisObj: Any?,
        args: Array<Any?>,
        result: Any?,
    ): MethodHookParam
    {
        val unsafeClass = Class.forName("sun.misc.Unsafe")
        val unsafeField = unsafeClass.getDeclaredField("theUnsafe")
        unsafeField.isAccessible = true
        val unsafe = unsafeField.get(null)
        val allocateMethod = unsafeClass.getMethod(
            "allocateInstance",
            Class::class.java,
        )
        val param = allocateMethod.invoke(
            unsafe,
            MethodHookParam::class.java,
        ) as MethodHookParam

        setFieldAny(param, "thisObject", thisObj)
        setFieldAny(param, "args", args)
        setFieldAny(param, "result", result)
        return param
    }

    private fun setFieldAny(
        obj: Any,
        name: String,
        value: Any?,
    )
    {
        var current: Class<*>? = obj.javaClass
        while (current != null && current != Any::class.java) {
            try {
                val field = current.getDeclaredField(name)
                field.isAccessible = true
                field.set(obj, value)
                return
            } catch (_: NoSuchFieldException) {
                current = current.superclass
            }
        }
    }

    private fun createContext(
        initialReturn: Any? = "original_return",
        runtimeState: RuntimeStateStore? = null,
        eventBus: RuntimeEventBus? = null,
        hookId: String = "test_hook",
    ): ActionContext
    {
        val param = createParam(
            null,
            arrayOf<Any?>("hello", 100),
            initialReturn,
        )
        val ctx = ActionContext(
            param = param,
            classLoader = ActionExecutorUnitTest::class.java.classLoader!!,
            pkg = "com.test.pkg",
            hookId = hookId,
            runtimeState = runtimeState,
            eventBus = eventBus,
        )
        ctx.result = initialReturn
        return ctx
    }

    @Test
    fun testConditionEvaluation()
    {
        val ctx = createContext()

        val condEq = JSONObject(
            """{"path":"args[0]","op":"eq","value":"hello"}"""
        )
        assertTrue(
            ActionExecutor.evaluateCondition(ctx, condEq)
        )

        val condNeq = JSONObject(
            """{"path":"args[0]","op":"neq","value":"world"}"""
        )
        assertTrue(
            ActionExecutor.evaluateCondition(ctx, condNeq)
        )

        val condContains = JSONObject(
            """{"path":"args[0]","op":"contains","value":"ell"}"""
        )
        assertTrue(
            ActionExecutor.evaluateCondition(
                ctx,
                condContains,
            )
        )

        val condRegex = JSONObject(
            """{"path":"args[0]","op":"regex","value":"^h.*o$"}"""
        )
        assertTrue(
            ActionExecutor.evaluateCondition(
                ctx,
                condRegex,
            )
        )

        val condGt = JSONObject(
            """{"path":"args[1]","op":"gt","value":50}"""
        )
        assertTrue(
            ActionExecutor.evaluateCondition(ctx, condGt)
        )

        val condLte = JSONObject(
            """{"path":"args[1]","op":"<=","value":100}"""
        )
        assertTrue(
            ActionExecutor.evaluateCondition(ctx, condLte)
        )

        val condNull = JSONObject(
            """{"path":"ret","op":"not_null"}"""
        )
        assertTrue(
            ActionExecutor.evaluateCondition(
                ctx,
                condNull,
            )
        )
    }

    @Test
    fun testMutatePathAndNestedPath()
    {
        val ctx = createContext()
        val holder = SampleHolder()
        ctx.thisObject = holder

        assertTrue(
            ActionExecutor.mutatePath(
                ctx,
                "\$v1",
                "register_value",
            )
        )
        assertEquals(
            "register_value",
            ctx.registers["\$v1"],
        )

        assertTrue(
            ActionExecutor.mutatePath(
                ctx,
                "ret",
                "new_return_val",
            )
        )
        assertEquals("new_return_val", ctx.result)

        assertTrue(
            ActionExecutor.mutatePath(
                ctx,
                "this.title",
                "updated_title",
            )
        )
        assertEquals("updated_title", holder.title)

        assertTrue(
            ActionExecutor.mutatePath(
                ctx,
                "this.info['status']",
                "tampered",
            )
        )
        assertEquals("tampered", holder.info["status"])

        assertEquals(
            "tampered",
            ActionExecutor.resolvePath(
                ctx,
                "this.info.status",
            ),
        )
    }

    @Test
    fun testRuntimeStateActionsAndPathConditions()
    {
        val state = RuntimeStateStore(
            packageName = "com.test.pkg",
        )
        val ctx = createContext(
            runtimeState = state,
        )

        val beforeActions = JSONArray()
            .put(
                JSONObject().apply {
                    put("action", "set_state")
                    put("scope", "process")
                    put("key", "last_text")
                    put("value", "\${args[0]}")
                }
            )
            .put(
                JSONObject().apply {
                    put("action", "increment_state")
                    put("scope", "hook")
                    put("key", "hits")
                    put("delta", 2)
                }
            )
            .put(
                JSONObject().apply {
                    put("action", "append_state")
                    put("scope", "package")
                    put("key", "history")
                    put("value", "\${args[0]}")
                }
            )

        val actionJson = JSONObject().put(
            "before_actions",
            beforeActions,
        )
        ActionExecutor.executeActions(
            ctx,
            actionJson,
            "before",
        )

        assertEquals(
            "hello",
            state.get(
                "process",
                "last_text",
                "test_hook",
            ),
        )
        assertEquals(
            2L,
            state.get(
                "hook",
                "hits",
                "test_hook",
            ),
        )
        assertEquals(
            listOf("hello"),
            state.get(
                "package",
                "history",
                "test_hook",
            ),
        )
        assertEquals(
            "hello",
            ActionExecutor.resolvePath(
                ctx,
                "state.process.last_text",
            ),
        )

        val condition = JSONObject()
            .put("path", "state.hook.hits")
            .put("op", "eq")
            .put("value", 2)

        assertTrue(
            ActionExecutor.evaluateCondition(
                ctx,
                condition,
            )
        )
    }

    @Test
    fun testEmitEventCanDriveAnotherHandlerThroughSharedState()
    {
        val state = RuntimeStateStore(
            packageName = "com.test.pkg",
        )
        val bus = RuntimeEventBus()

        val listener = JSONObject()
            .put("name", "vip_changed")
            .put(
                "actions",
                JSONArray()
                    .put(
                        JSONObject().apply {
                            put("action", "set_state")
                            put("scope", "process")
                            put("key", "vip_value")
                            put("value", "\${event.vip}")
                        }
                    )
                    .put(
                        JSONObject().apply {
                            put("action", "increment_state")
                            put("scope", "process")
                            put("key", "event_hits")
                        }
                    ),
            )

        bus.subscribe(
            ownerHookId = "listener_hook",
            eventName = "vip_changed",
        ) { event ->
            val listenerCtx = ActionContext(
                param = null,
                classLoader = (
                    ActionExecutorUnitTest::class.java
                        .classLoader!!
                ),
                pkg = "com.test.pkg",
                hookId = "listener_hook",
                runtimeState = state,
                eventBus = bus,
                runtimeEvent = event,
            )
            ActionExecutor.executeEventHandler(
                listenerCtx,
                listener,
            )
        }

        val emitterCtx = createContext(
            runtimeState = state,
            eventBus = bus,
            hookId = "emitter_hook",
        )
        val emitAction = JSONObject().put(
            "before_actions",
            JSONArray().put(
                JSONObject().apply {
                    put("action", "emit_event")
                    put("name", "vip_changed")
                    put(
                        "payload",
                        JSONObject().put(
                            "vip",
                            "\${args[0]}",
                        ),
                    )
                }
            ),
        )

        ActionExecutor.executeActions(
            emitterCtx,
            emitAction,
            "before",
        )

        assertEquals(
            "hello",
            state.get(
                "process",
                "vip_value",
                "listener_hook",
            ),
        )
        assertEquals(
            1L,
            state.get(
                "process",
                "event_hits",
                "listener_hook",
            ),
        )
    }

    @Test
    fun testReplaceArgsAndReturnActions()
    {
        val ctx = createContext()
        val actionJson = JSONObject(
            """
            {
                "replace_args": [
                    {"index": 0, "value": "replaced_arg0"},
                    {"index": 1, "value": 999}
                ],
                "skip_original": true,
                "replace_return": {"value": "mocked_return"}
            }
            """.trimIndent()
        )

        ActionExecutor.executeActions(
            ctx,
            actionJson,
            "before",
        )

        assertEquals("replaced_arg0", ctx.args!![0])
        assertEquals(999, ctx.args!![1])
        assertEquals("mocked_return", ctx.result)
    }
}
