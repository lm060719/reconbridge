package com.reconbridge.tracer

import de.robv.android.xposed.XC_MethodHook.MethodHookParam
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SampleHolder {
    var title: String = "default_title"
    val info: MutableMap<String, Any> = mutableMapOf("status" to "ok", "code" to 200)
}

class ActionExecutorUnitTest {

    private fun createParam(thisObj: Any?, args: Array<Any?>, result: Any?): MethodHookParam {
        val unsafeClass = Class.forName("sun.misc.Unsafe")
        val unsafeField = unsafeClass.getDeclaredField("theUnsafe")
        unsafeField.isAccessible = true
        val unsafe = unsafeField.get(null)
        val allocateMethod = unsafeClass.getMethod("allocateInstance", Class::class.java)
        val param = allocateMethod.invoke(unsafe, MethodHookParam::class.java) as MethodHookParam
        println("METHODHOOKPARAM DECLARED FIELDS: " + MethodHookParam::class.java.declaredFields.map { it.name })
        println("SUPERCLASS DECLARED FIELDS: " + MethodHookParam::class.java.superclass?.declaredFields?.map { it.name })
        setFieldAny(param, "thisObject", thisObj)
        setFieldAny(param, "args", args)
        setFieldAny(param, "result", result)
        return param
    }


    private fun setFieldAny(obj: Any, name: String, value: Any?) {
        var c: Class<*>? = obj.javaClass
        while (c != null && c != Any::class.java) {
            try {
                val f = c.getDeclaredField(name)
                f.isAccessible = true
                f.set(obj, value)
                return
            } catch (_: NoSuchFieldException) {
                c = c.superclass
            }
        }
    }





    private fun createContext(
        initialReturn: Any? = "original_return",
        runtimeState: RuntimeStateStore? = null,
        eventBus: RuntimeEventBus? = null,
        hookId: String = "test_hook",
    ): ActionContext {
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
    fun testConditionEvaluation() {
        val ctx = createContext()

        // eq / equals
        val condEq = JSONObject("""{"path": "args[0]", "op": "eq", "value": "hello"}""")
        assertTrue(ActionExecutor.evaluateCondition(ctx, condEq))

        val condNeq = JSONObject("""{"path": "args[0]", "op": "neq", "value": "world"}""")
        assertTrue(ActionExecutor.evaluateCondition(ctx, condNeq))

        // contains
        val condContains = JSONObject("""{"path": "args[0]", "op": "contains", "value": "ell"}""")
        assertTrue(ActionExecutor.evaluateCondition(ctx, condContains))

        // regex
        val condRegex = JSONObject("""{"path": "args[0]", "op": "regex", "value": "^h.*o$"}""")
        assertTrue(ActionExecutor.evaluateCondition(ctx, condRegex))

        // numeric gt / lte
        val condGt = JSONObject("""{"path": "args[1]", "op": "gt", "value": 50}""")
        assertTrue(ActionExecutor.evaluateCondition(ctx, condGt))

        val condLte = JSONObject("""{"path": "args[1]", "op": "<=", "value": 100}""")
        assertTrue(ActionExecutor.evaluateCondition(ctx, condLte))

        // null checks
        val condNull = JSONObject("""{"path": "ret", "op": "not_null"}""")
        assertTrue(ActionExecutor.evaluateCondition(ctx, condNull))
    }

    @Test
    fun testMutatePathAndNestedPath() {
        val ctx = createContext()
        val holder = SampleHolder()
        ctx.thisObject = holder

        // Mutate register
        assertTrue(ActionExecutor.mutatePath(ctx, "\$v1", "register_value"))
        assertEquals("register_value", ctx.registers["\$v1"])

        // Mutate ret
        assertTrue(ActionExecutor.mutatePath(ctx, "ret", "new_return_val"))
        assertEquals("new_return_val", ctx.result)

        // Mutate nested field in this
        assertTrue(ActionExecutor.mutatePath(ctx, "this.title", "updated_title"))
        assertEquals("updated_title", holder.title)

        // Mutate nested map key in this.info
        assertTrue(ActionExecutor.mutatePath(ctx, "this.info['status']", "tampered"))
        assertEquals("tampered", holder.info["status"])

        // Resolve path check
        val resStatus = ActionExecutor.resolvePath(ctx, "this.info.status")
        assertEquals("tampered", resStatus)
    }

    @Test
    fun testRuntimeStateActionsAndPathConditions() {
        val state = RuntimeStateStore(
            packageName = "com.test.pkg",
        )
        val ctx = createContext(
            runtimeState = state,
        )
        val actionJson = JSONObject(
            """
            {
              "before_actions": [
                {
                  "action": "set_state",
                  "scope": "process",
                  "key": "last_text",
                  "value": "${args[0]}"
                },
                {
                  "action": "increment_state",
                  "scope": "hook",
                  "key": "hits",
                  "delta": 2
                },
                {
                  "action": "append_state",
                  "scope": "package",
                  "key": "history",
                  "value": "${args[0]}"
                }
              ]
            }
            """.trimIndent()
        )

        ActionExecutor.executeActions(
            ctx,
            actionJson,
            "before",
        )

        assertEquals(
            "hello",
            state.get("process", "last_text", "test_hook"),
        )
        assertEquals(
            2L,
            state.get("hook", "hits", "test_hook"),
        )
        assertEquals(
            listOf("hello"),
            state.get("package", "history", "test_hook"),
        )
        assertEquals(
            "hello",
            ActionExecutor.resolvePath(
                ctx,
                "state.process.last_text",
            ),
        )

        val condition = JSONObject(
            """
            {
              "path": "state.hook.hits",
              "op": "eq",
              "value": 2
            }
            """.trimIndent()
        )
        assertTrue(
            ActionExecutor.evaluateCondition(
                ctx,
                condition,
            )
        )
    }

    @Test
    fun testEmitEventCanDriveAnotherHandlerThroughSharedState() {
        val state = RuntimeStateStore(
            packageName = "com.test.pkg",
        )
        val bus = RuntimeEventBus()
        val listener = JSONObject(
            """
            {
              "name": "vip_changed",
              "actions": [
                {
                  "action": "set_state",
                  "scope": "process",
                  "key": "vip_value",
                  "value": "${event.vip}"
                },
                {
                  "action": "increment_state",
                  "scope": "process",
                  "key": "event_hits"
                }
              ]
            }
            """.trimIndent()
        )

        bus.subscribe(
            ownerHookId = "listener_hook",
            eventName = "vip_changed",
        ) { event ->
            val listenerCtx = ActionContext(
                param = null,
                classLoader = ActionExecutorUnitTest::class.java.classLoader!!,
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
        val emitAction = JSONObject(
            """
            {
              "before_actions": [
                {
                  "action": "emit_event",
                  "name": "vip_changed",
                  "payload": {
                    "vip": "${args[0]}"
                  }
                }
              ]
            }
            """.trimIndent()
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
    fun testReplaceArgsAndReturnActions() {
        val ctx = createContext()
        val actionJson = JSONObject("""
            {
                "replace_args": [
                    {"index": 0, "value": "replaced_arg0"},
                    {"index": 1, "value": 999}
                ],
                "skip_original": true,
                "replace_return": {"value": "mocked_return"}
            }
        """.trimIndent())

        ActionExecutor.executeActions(ctx, actionJson, "before")

        assertEquals("replaced_arg0", ctx.args!![0])
        assertEquals(999, ctx.args!![1])
        assertEquals("mocked_return", ctx.result)
    }
}
