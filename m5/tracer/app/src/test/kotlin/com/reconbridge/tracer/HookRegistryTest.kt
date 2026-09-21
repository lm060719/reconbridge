package com.reconbridge.tracer

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class HookRegistryTest
{
    private class FakeHandle : LiveHookHandle
    {
        var unhooked = false

        override fun unhook()
        {
            unhooked = true
        }
    }

    private data class InstallCall(
        val id: String,
        val handle: FakeHandle,
    )

    private fun target(
        id: String,
        method: String = "check",
        ret: Boolean = true,
    ): JSONObject
    {
        return JSONObject().apply {
            put("kind", "java")
            put("id", id)
            put("class", "com.example.Target")
            put("method", method)
            put(
                "action",
                JSONObject().apply {
                    put("replace_return", ret)
                }
            )
        }
    }

    @Test
    fun reconcileAddsKeepsReplacesAndRemovesLiveHooks()
    {
        val calls = mutableListOf<InstallCall>()
        val registry = HookRegistry(
            packageName = "com.example",
            processName = "com.example",
            pid = 123,
            initialClassLoader = javaClass.classLoader!!,
        ) { spec, _ ->
            val handle = FakeHandle()
            calls.add(InstallCall(spec.getString("id"), handle))
            HookInstallResult(
                handles = listOf(handle),
                members = listOf(
                    "com.example.Target.${spec.getString("method")}()"
                ),
            )
        }

        val first = registry.reconcile(
            JSONArray().put(target("a")).put(target("b", "open"))
        )

        assertEquals(2, first.added)
        assertEquals(0, first.replaced)
        assertEquals(2, registry.snapshotJson().getInt("installed_count"))

        val oldA = calls.first { it.id == "a" }.handle
        val oldB = calls.first { it.id == "b" }.handle

        val second = registry.reconcile(
            JSONArray().put(target("a", ret = false))
        )

        assertEquals(0, second.added)
        assertEquals(1, second.replaced)
        assertEquals(1, second.removed)
        assertTrue(oldA.unhooked)
        assertTrue(oldB.unhooked)
        assertEquals(1, registry.snapshotJson().getInt("installed_count"))

        val newA = calls.last { it.id == "a" }.handle
        val third = registry.reconcile(
            JSONArray().put(target("a", ret = false))
        )

        assertEquals(1, third.unchanged)
        assertFalse(newA.unhooked)

        val fourth = registry.reconcile(JSONArray())
        assertEquals(1, fourth.removed)
        assertTrue(newA.unhooked)
        assertEquals(0, registry.snapshotJson().getInt("installed_count"))
    }

    @Test
    fun failedReplacementKeepsExistingHookInstalled()
    {
        val firstHandle = FakeHandle()
        var installs = 0
        val registry = HookRegistry(
            packageName = "com.example",
            processName = "com.example:remote",
            pid = 456,
            initialClassLoader = javaClass.classLoader!!,
        ) { spec, _ ->
            installs++
            if (spec.optBoolean("fail", false)) {
                throw IllegalStateException("boom")
            }
            HookInstallResult(
                handles = listOf(firstHandle),
                members = listOf("Target.check()"),
            )
        }

        registry.reconcile(JSONArray().put(target("a")))

        val replacement = target("a").apply {
            put("fail", true)
        }
        val result = registry.reconcile(
            JSONArray().put(replacement)
        )

        assertEquals(1, result.failed)
        assertEquals(0, result.replaced)
        assertFalse(firstHandle.unhooked)
        assertEquals(1, registry.snapshotJson().getInt("installed_count"))
        assertEquals(2, installs)
    }

    @Test
    fun missingClassBecomesPendingAndInstallsWhenDynamicLoaderAppears()
    {
        val mainLoader = object : ClassLoader(null) {}
        val pluginLoader = object : ClassLoader(null) {}
        val handle = FakeHandle()
        var pluginInstalls = 0

        val registry = HookRegistry(
            packageName = "com.example",
            processName = "com.example",
            pid = 321,
            initialClassLoader = mainLoader,
        ) { spec, loader ->
            if (loader !== pluginLoader) {
                throw ClassNotFoundException(spec.getString("class"))
            }
            pluginInstalls++
            HookInstallResult(
                handles = listOf(handle),
                members = listOf("plugin.Target.check()"),
            )
        }

        val target = target("late").apply {
            put("class", "plugin.Target")
        }
        val first = registry.reconcile(
            JSONArray().put(target)
        )

        assertEquals(0, first.failed)
        assertEquals(1, first.pending)
        assertTrue(registry.hasPending())
        assertEquals(
            setOf("plugin.Target"),
            registry.pendingClassNames(),
        )

        val before = registry.snapshotJson()
        assertEquals(0, before.getInt("installed_count"))
        assertEquals(1, before.getInt("pending_count"))
        assertEquals(1, before.getInt("class_loader_count"))

        val resolved = registry.onLoaderAvailable(
            pluginLoader,
            "DexClassLoader.<init>",
        )

        assertEquals(1, resolved.added)
        assertEquals(0, resolved.pending)
        assertEquals(1, pluginInstalls)
        assertFalse(registry.hasPending())

        val after = registry.snapshotJson()
        assertEquals(1, after.getInt("installed_count"))
        assertEquals(0, after.getInt("pending_count"))
        assertEquals(2, after.getInt("class_loader_count"))
        val installed = after.getJSONArray("hooks").getJSONObject(0)
        assertEquals("late", installed.getString("id"))
        assertEquals("cl2", installed.getString("class_loader_id"))
    }

    @Test
    fun pendingHookCanBeRemovedBeforeClassAppears()
    {
        val mainLoader = object : ClassLoader(null) {}
        val registry = HookRegistry(
            packageName = "com.example",
            processName = "com.example",
            pid = 654,
            initialClassLoader = mainLoader,
        ) { spec, _ ->
            throw ClassNotFoundException(spec.getString("class"))
        }

        val target = target("late").apply {
            put("class", "plugin.Target")
        }
        registry.reconcile(JSONArray().put(target))
        assertTrue(registry.hasPending())

        val removed = registry.reconcile(JSONArray())

        assertFalse(registry.hasPending())
        assertEquals(0, removed.pending)
        assertEquals(
            0,
            registry.snapshotJson().getInt("pending_count"),
        )
    }

    @Test
    fun classLoadedOnlyRetriesMatchingPendingClass()
    {
        val mainLoader = object : ClassLoader(null) {}
        val pluginLoader = object : ClassLoader(null) {}
        val attempts = mutableListOf<String>()

        val registry = HookRegistry(
            packageName = "com.example",
            processName = "com.example",
            pid = 987,
            initialClassLoader = mainLoader,
        ) { spec, loader ->
            val className = spec.getString("class")
            attempts.add(className)
            if (
                loader === pluginLoader &&
                className == "plugin.Second"
            ) {
                HookInstallResult(
                    handles = listOf(FakeHandle()),
                    members = listOf("plugin.Second.check()"),
                )
            } else {
                throw ClassNotFoundException(className)
            }
        }

        val first = target("first").apply {
            put("class", "plugin.First")
        }
        val second = target("second").apply {
            put("class", "plugin.Second")
        }
        registry.reconcile(
            JSONArray().put(first).put(second)
        )
        attempts.clear()

        val result = registry.onClassLoaded(
            pluginLoader,
            "plugin.Second",
        )

        assertEquals(1, result.added)
        assertEquals(
            listOf("plugin.Second"),
            attempts,
        )
        assertEquals(
            setOf("plugin.First"),
            registry.pendingClassNames(),
        )
    }

    @Test
    fun fingerprintIsStableAcrossObjectKeyOrder()
    {
        val left = JSONObject().apply {
            put("id", "a")
            put("class", "com.example.Target")
            put("capture", JSONObject().apply {
                put("when", "after")
                put("stack", false)
            })
        }
        val right = JSONObject().apply {
            put("capture", JSONObject().apply {
                put("stack", false)
                put("when", "after")
            })
            put("class", "com.example.Target")
            put("id", "a")
        }

        assertEquals(
            HookRegistry.fingerprint(left),
            HookRegistry.fingerprint(right),
        )
    }

    @Test
    fun snapshotReportsActualMembersAndCapabilities()
    {
        val registry = HookRegistry(
            packageName = "com.example",
            processName = "com.example:core",
            pid = 789,
            initialClassLoader = javaClass.classLoader!!,
        ) { _, _ ->
            HookInstallResult(
                handles = listOf(FakeHandle(), FakeHandle()),
                members = listOf(
                    "Target.check(int)",
                    "Target.check(String)",
                ),
            )
        }

        registry.reconcile(JSONArray().put(target("x")))
        val snapshot = registry.snapshotJson()

        assertEquals("com.example", snapshot.getString("package"))
        assertEquals("com.example:core", snapshot.getString("process"))
        assertEquals(789, snapshot.getInt("pid"))
        assertTrue(snapshot.getBoolean("live_unhook"))
        assertTrue(snapshot.getBoolean("replace_supported"))
        assertEquals(1, snapshot.getInt("installed_count"))

        val hook = snapshot.getJSONArray("hooks").getJSONObject(0)
        assertEquals("x", hook.getString("id"))
        assertEquals(2, hook.getInt("member_count"))
        assertEquals(2, hook.getJSONArray("members").length())
    }
}
