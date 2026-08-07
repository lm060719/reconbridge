package com.reconbridge.tracer

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Collections
import java.util.HashSet

class ConfigAndTargetTest {

    @Test
    fun testJsonConfigParsing() {
        val jsonStr = """
            {
                "package": "com.example.app",
                "debug": true,
                "targets": [
                    {
                        "kind": "java",
                        "id": "target1",
                        "class": "com.example.app.Security",
                        "method": "check"
                    },
                    {
                        "kind": "native",
                        "id": "native1",
                        "symbol": "Java_com_example_app_nativeCheck"
                    }
                ]
            }
        """.trimIndent()

        val cfg = JSONObject(jsonStr)
        assertEquals("com.example.app", cfg.getString("package"))
        assertTrue(cfg.getBoolean("debug"))

        val targets = cfg.getJSONArray("targets")
        assertEquals(2, targets.length())

        val t0 = targets.getJSONObject(0)
        assertEquals("java", t0.getString("kind"))
        assertEquals("target1", t0.getString("id"))
    }

    @Test
    fun testHookTargetDeduplicationAndFiltering() {
        val jsonStr = """
            {
                "targets": [
                    {"kind": "java", "id": "id1", "class": "A", "method": "m1"},
                    {"kind": "native", "id": "id2", "symbol": "sym"},
                    {"kind": "java", "id": "id1", "class": "A", "method": "m1_dup"},
                    {"kind": "java", "id": "id3", "class": "B", "method": "m2"}
                ]
            }
        """.trimIndent()

        val targets = JSONObject(jsonStr).getJSONArray("targets")
        val installedIds = Collections.synchronizedSet(HashSet<String>())
        val validJavaTargets = mutableListOf<JSONObject>()

        for (i in 0 until targets.length()) {
            val t = targets.optJSONObject(i) ?: continue
            if (t.optString("kind", "native") != "java") continue
            val id = t.optString("id", "j$i")
            if (installedIds.contains(id)) continue

            installedIds.add(id)
            validJavaTargets.add(t)
        }

        assertEquals(2, validJavaTargets.size)
        assertEquals("id1", validJavaTargets[0].getString("id"))
        assertEquals("id3", validJavaTargets[1].getString("id"))
        assertTrue(installedIds.contains("id1"))
        assertTrue(installedIds.contains("id3"))
        assertFalse(installedIds.contains("id2"))
    }
}
