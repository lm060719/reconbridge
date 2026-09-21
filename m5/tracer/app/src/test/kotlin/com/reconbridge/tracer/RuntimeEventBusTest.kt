package com.reconbridge.tracer

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class RuntimeEventBusTest
{
    @Test
    fun subscriptionCanBeLiveUnhooked()
    {
        val bus = RuntimeEventBus()
        var hits = 0
        val handle = bus.subscribe(
            ownerHookId = "listener",
            eventName = "changed",
        ) {
            hits++
        }

        assertEquals(
            1,
            bus.emit(
                RuntimeEvent(
                    name = "changed",
                    payload = emptyMap(),
                    sourceHookId = "source",
                )
            ),
        )
        assertEquals(1, hits)

        handle.unhook()

        assertEquals(
            0,
            bus.emit(
                RuntimeEvent(
                    name = "changed",
                    payload = emptyMap(),
                    sourceHookId = "source",
                )
            ),
        )
        assertEquals(1, hits)
    }

    @Test
    fun recursiveEventEmissionIsDepthLimited()
    {
        val bus = RuntimeEventBus(
            maxDepth = 3,
        )
        var callbacks = 0

        bus.subscribe(
            ownerHookId = "loop",
            eventName = "loop",
        ) {
            callbacks++
            bus.emit(
                RuntimeEvent(
                    name = "loop",
                    payload = emptyMap(),
                    sourceHookId = "loop",
                )
            )
        }

        bus.emit(
            RuntimeEvent(
                name = "loop",
                payload = emptyMap(),
                sourceHookId = "source",
            )
        )

        assertEquals(3, callbacks)
        assertTrue(
            bus.snapshotJson().getLong("dropped_depth") > 0
        )
    }

    @Test
    fun eventPayloadIsAvailableAtRootAndPayloadPath()
    {
        val event = RuntimeEvent(
            name = "vip_changed",
            payload = mapOf(
                "vip" to true,
                "user" to "u1",
            ),
            sourceHookId = "source",
        )
        val map = event.asMap()

        assertEquals(true, map["vip"])
        assertEquals("vip_changed", map["name"])
        @Suppress("UNCHECKED_CAST")
        val payload = map["payload"] as Map<String, Any?>
        assertEquals("u1", payload["user"])
    }
}
