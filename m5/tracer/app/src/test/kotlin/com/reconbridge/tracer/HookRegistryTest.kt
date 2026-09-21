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
        ) { spec ->
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
        ) { spec ->
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
        ) {
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
