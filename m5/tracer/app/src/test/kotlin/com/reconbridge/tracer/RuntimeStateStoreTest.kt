package com.reconbridge.tracer

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RuntimeStateStoreTest
{
    @Test
    fun stateScopesAreIsolatedAndHookScopeCanBeCleared()
    {
        val store = RuntimeStateStore(
            packageName = "com.example",
        )

        store.set("process", "flag", "p", "hookA")
        store.set("package", "flag", "pkg", "hookA")
        store.set("hook", "flag", "a", "hookA")
        store.set("hook", "flag", "b", "hookB")
        store.set("thread", "flag", "t", "hookA")

        assertEquals("p", store.get("process", "flag", "hookA"))
        assertEquals("pkg", store.get("package", "flag", "hookA"))
        assertEquals("a", store.get("hook", "flag", "hookA"))
        assertEquals("b", store.get("hook", "flag", "hookB"))
        assertEquals("t", store.get("thread", "flag", "hookA"))

        assertEquals(1, store.clearHook("hookA"))
        assertFalse(store.contains("hook", "flag", "hookA"))
        assertTrue(store.contains("hook", "flag", "hookB"))
        assertEquals("p", store.get("process", "flag", "hookA"))
    }

    @Test
    fun stateMapsAndAppendListsAreBounded()
    {
        val store = RuntimeStateStore(
            packageName = "com.example",
            maxKeysPerScope = 2,
            maxHookScopes = 2,
            maxAppendItems = 3,
        )

        store.set("process", "a", 1)
        store.set("process", "b", 2)
        store.set("process", "c", 3)

        val snapshot = store.snapshotJson()
            .getJSONObject("process")
        assertEquals(2, snapshot.getInt("count"))
        assertFalse(
            snapshot.getJSONObject("values").has("a")
        )

        for (value in 1..5) {
            store.append(
                "process",
                "items",
                value,
            )
        }
        assertEquals(
            listOf(3, 4, 5),
            store.get("process", "items"),
        )
    }

    @Test
    fun concurrentIncrementDoesNotLoseUpdates()
    {
        val store = RuntimeStateStore(
            packageName = "com.example",
        )
        val threads = (0 until 8).map {
            Thread {
                repeat(200) {
                    store.increment(
                        "process",
                        "hits",
                        1.0,
                    )
                }
            }
        }

        for (thread in threads) {
            thread.start()
        }
        for (thread in threads) {
            thread.join()
        }

        assertEquals(
            1600L,
            store.get("process", "hits"),
        )
    }

    @Test
    fun statePathReadWriteUsesCurrentHookScope()
    {
        val store = RuntimeStateStore(
            packageName = "com.example",
        )

        assertTrue(
            store.setPath(
                "state.hook.enabled",
                true,
                "hookA",
            )
        )
        assertEquals(
            true,
            store.resolve(
                "state.hook.enabled",
                "hookA",
            ),
        )
        assertTrue(
            store.resolve(
                "state.hook.enabled",
                "hookB",
            ) === ActionExecutor.MISSING
        )
    }
}
