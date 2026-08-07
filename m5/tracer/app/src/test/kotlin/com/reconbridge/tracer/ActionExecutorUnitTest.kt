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





    private fun createContext(initialReturn: Any? = "original_return"): ActionContext {
        val param = createParam(null, arrayOf<Any?>("hello", 100), initialReturn)
        val ctx = ActionContext(param, ActionExecutorUnitTest::class.java.classLoader!!, "com.test.pkg")
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
        ctx.param.thisObject = holder

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
