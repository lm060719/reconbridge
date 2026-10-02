package com.reconbridge.tracer

import org.json.JSONArray
import org.json.JSONObject
import java.util.LinkedHashMap
import java.util.concurrent.atomic.AtomicLong

internal data class RuntimeEvent(
    val name: String,
    val payload: Map<String, Any?>,
    val sourceHookId: String,
    val ts: Long = System.currentTimeMillis(),
    val tid: Long = Thread.currentThread().id,
)
{
    fun asMap(): LinkedHashMap<String, Any?>
    {
        val out = LinkedHashMap<String, Any?>()
        out["name"] = name
        out["source_hook"] = sourceHookId
        out["ts"] = ts
        out["tid"] = tid
        out["payload"] = payload

        // payload 同时平铺到 event 根，便于 ${event.vip}。
        for ((key, value) in payload) {
            if (!out.containsKey(key)) {
                out[key] = value
            }
        }
        return out
    }
}

/**
 * 进程内同步 Event Bus。
 *
 * 事件在当前 Hook 线程同步分发，这样 handler 对 Runtime State 的修改可立刻影响后续 Hook。
 * ThreadLocal 深度限制防止 emit_event -> handler -> emit_event 形成无限递归。
 */
internal class RuntimeEventBus(
    private val maxHandlers: Int = 256,
    private val maxDepth: Int = 16,
)
{
    private data class Subscription(
        val id: Long,
        val ownerHookId: String,
        val eventName: String,
        val createdAt: Long,
        val handler: (RuntimeEvent) -> Unit,
    )

    private val lock = Any()
    private val subscriptions = LinkedHashMap<Long, Subscription>()
    private val nextId = AtomicLong(1)
    private val emitted = AtomicLong()
    private val delivered = AtomicLong()
    private val droppedDepth = AtomicLong()
    private val handlerErrors = AtomicLong()
    private val depth = ThreadLocal<Int>()
    private val lastEventLock = Any()
    private val recentNames = ArrayDeque<String>()

    fun subscribe(
        ownerHookId: String,
        eventName: String,
        handler: (RuntimeEvent) -> Unit,
    ): LiveHookHandle
    {
        require(eventName.isNotBlank()) {
            "event name 不能为空"
        }

        val id: Long
        synchronized(lock) {
            if (subscriptions.size >= maxHandlers) {
                throw IllegalStateException(
                    "RuntimeEventBus handler 数量超过上限 " + maxHandlers
                )
            }
            id = nextId.getAndIncrement()
            subscriptions[id] = Subscription(
                id = id,
                ownerHookId = ownerHookId,
                eventName = eventName,
                createdAt = System.currentTimeMillis(),
                handler = handler,
            )
        }

        return object : LiveHookHandle
        {
            override fun unhook()
            {
                synchronized(lock) {
                    subscriptions.remove(id)
                }
            }
        }
    }

    fun emit(event: RuntimeEvent): Int
    {
        val currentDepth = depth.get() ?: 0
        if (currentDepth >= maxDepth) {
            droppedDepth.incrementAndGet()
            return 0
        }

        val listeners = synchronized(lock) {
            subscriptions.values
                .filter { it.eventName == event.name }
                .toList()
        }

        emitted.incrementAndGet()
        rememberEvent(event.name)

        if (listeners.isEmpty()) {
            return 0
        }

        depth.set(currentDepth + 1)
        var handled = 0
        try {
            for (listener in listeners) {
                try {
                    listener.handler(event)
                    handled++
                    delivered.incrementAndGet()
                } catch (_: Throwable) {
                    handlerErrors.incrementAndGet()
                }
            }
        } finally {
            if (currentDepth == 0) {
                depth.remove()
            } else {
                depth.set(currentDepth)
            }
        }
        return handled
    }

    fun clearOwner(ownerHookId: String): Int
    {
        synchronized(lock) {
            val ids = subscriptions.values
                .filter { it.ownerHookId == ownerHookId }
                .map { it.id }
            for (id in ids) {
                subscriptions.remove(id)
            }
            return ids.size
        }
    }

    fun snapshotJson(): JSONObject
    {
        val handlers = JSONArray()
        synchronized(lock) {
            for (row in subscriptions.values) {
                handlers.put(
                    JSONObject().apply {
                        put("owner_hook_id", row.ownerHookId)
                        put("event", row.eventName)
                        put("created_at", row.createdAt)
                    }
                )
            }
        }

        val recent = JSONArray()
        synchronized(lastEventLock) {
            for (name in recentNames) {
                recent.put(name)
            }
        }

        return JSONObject().apply {
            put("enabled", true)
            put("synchronous", true)
            put("handler_count", handlers.length())
            put("max_handlers", maxHandlers)
            put("max_depth", maxDepth)
            put("emitted", emitted.get())
            put("delivered", delivered.get())
            put("dropped_depth", droppedDepth.get())
            put("handler_errors", handlerErrors.get())
            put("handlers", handlers)
            put("recent_events", recent)
        }
    }

    private fun rememberEvent(name: String)
    {
        synchronized(lastEventLock) {
            recentNames.addLast(name)
            while (recentNames.size > 20) {
                recentNames.removeFirst()
            }
        }
    }
}
