package com.reconbridge.tracer

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class LifecycleTriggerTest
{
    @Test
    fun normalizeLifecycleEventNames()
    {
        assertEquals(
            "lifecycle.activity_resumed",
            LifecycleTrigger.normalizeEventName("resumed"),
        )
        assertEquals(
            "lifecycle.activity_paused",
            LifecycleTrigger.normalizeEventName("activity_paused"),
        )
        assertEquals(
            "lifecycle.application_attached",
            LifecycleTrigger.normalizeEventName(
                "application_attached"
            ),
        )
        assertEquals(
            "lifecycle.activity_created",
            LifecycleTrigger.normalizeEventName(
                "lifecycle.activity_created"
            ),
        )
    }

    @Test
    fun normalizeHandlerMarksLifecycleTrigger()
    {
        val handler = JSONObject()
            .put("stage", "resumed")
            .put("activity", "VipActivity")

        val normalized = LifecycleTrigger.normalizeHandler(handler)

        assertEquals(
            "lifecycle.activity_resumed",
            normalized.getString("name"),
        )
        assertTrue(
            normalized.getBoolean(
                "_recon_lifecycle_trigger"
            )
        )
        assertEquals(
            "VipActivity",
            normalized.getString("activity"),
        )
    }

    @Test
    fun activityFilterSupportsFullSimpleAndRegexNames()
    {
        val event = RuntimeEvent(
            name = "lifecycle.activity_resumed",
            payload = mapOf(
                "activity_class" to "com.example.VipActivity",
                "state" to "resumed",
            ),
            sourceHookId = "__lifecycle__",
        )

        val full = LifecycleTrigger.normalizeHandler(
            JSONObject()
                .put("stage", "resumed")
                .put(
                    "activity",
                    "com.example.VipActivity",
                )
        )
        assertTrue(
            LifecycleTrigger.matches(full, event)
        )

        val simple = LifecycleTrigger.normalizeHandler(
            JSONObject()
                .put("stage", "resumed")
                .put("activity", "VipActivity")
        )
        assertTrue(
            LifecycleTrigger.matches(simple, event)
        )

        val regex = LifecycleTrigger.normalizeHandler(
            JSONObject()
                .put("stage", "resumed")
                .put(
                    "activity_match",
                    "example\\..*Activity$",
                )
        )
        assertTrue(
            LifecycleTrigger.matches(regex, event)
        )

        val wrong = LifecycleTrigger.normalizeHandler(
            JSONObject()
                .put("stage", "resumed")
                .put("activity", "MainActivity")
        )
        assertFalse(
            LifecycleTrigger.matches(wrong, event)
        )
    }

    @Test
    fun ordinaryEventHandlerIsNotFiltered()
    {
        val handler = JSONObject()
            .put("name", "custom")
            .put("activity", "NeverMatches")

        val event = RuntimeEvent(
            name = "custom",
            payload = emptyMap(),
            sourceHookId = "source",
        )

        assertTrue(
            LifecycleTrigger.matches(handler, event)
        )
    }
}
