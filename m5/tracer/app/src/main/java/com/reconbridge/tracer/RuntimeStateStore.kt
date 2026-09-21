package com.reconbridge.tracer

import org.json.JSONArray
import org.json.JSONObject
import java.util.LinkedHashMap
import java.util.concurrent.atomic.AtomicLong

/**
 * 进程内 Runtime State。
 *
 * process/package/hook 都是当前 App 进程内的长期状态；thread 使用 ThreadLocal，
 * 不跨线程共享。所有长期 Map 都有 LRU 上限，避免错误配置无限增长。
 */
internal class RuntimeStateStore(
    private val packageName: String,
    private val maxKeysPerScope: Int = 256,
    private val maxHookScopes: Int = 128,
    private val maxAppendItems: Int = 128,
)
{
    private class BoundedStateMap(
        private val maxKeys: Int,
    )
    {
        private val values = object : LinkedHashMap<String, Any?>(
            16,
            0.75f,
            true,
        )
        {
            override fun removeEldestEntry(
                eldest: MutableMap.MutableEntry<String, Any?>?,
            ): Boolean
            {
                return size > maxKeys
            }
        }

        @Synchronized
        fun get(key: String): Any?
        {
            return values[key]
        }

        @Synchronized
        fun contains(key: String): Boolean
        {
            return values.containsKey(key)
        }

        @Synchronized
        fun set(key: String, value: Any?)
        {
            values[key] = value
        }

        @Synchronized
        fun remove(key: String): Any?
        {
            return values.remove(key)
        }

        @Synchronized
        fun clear(): Int
        {
            val count = values.size
            values.clear()
            return count
        }

        @Synchronized
        fun size(): Int
        {
            return values.size
        }

        @Synchronized
        fun snapshot(): LinkedHashMap<String, Any?>
        {
            return LinkedHashMap(values)
        }
    }

    private val processState = BoundedStateMap(maxKeysPerScope)
    private val packageState = BoundedStateMap(maxKeysPerScope)
    private val hookLock = Any()
    private val hookStates = object : LinkedHashMap<String, BoundedStateMap>(
        16,
        0.75f,
        true,
    )
    {
        override fun removeEldestEntry(
            eldest: MutableMap.MutableEntry<String, BoundedStateMap>?,
        ): Boolean
        {
            return size > maxHookScopes
        }
    }
    private val threadState = ThreadLocal<BoundedStateMap>()
    private val reads = AtomicLong()
    private val writes = AtomicLong()
    private val removes = AtomicLong()
    private val clears = AtomicLong()

    fun get(
        scope: String,
        key: String,
        hookId: String = "",
    ): Any?
    {
        if (key.isEmpty()) {
            return null
        }

        reads.incrementAndGet()
        return mapFor(scope, hookId, create = false)?.get(key)
    }

    fun contains(
        scope: String,
        key: String,
        hookId: String = "",
    ): Boolean
    {
        if (key.isEmpty()) {
            return false
        }

        reads.incrementAndGet()
        return mapFor(scope, hookId, create = false)?.contains(key) == true
    }

    fun set(
        scope: String,
        key: String,
        value: Any?,
        hookId: String = "",
    )
    {
        require(key.isNotEmpty()) {
            "state key 不能为空"
        }
        mapFor(scope, hookId, create = true)!!.set(key, value)
        writes.incrementAndGet()
    }

    fun remove(
        scope: String,
        key: String,
        hookId: String = "",
    ): Any?
    {
        if (key.isEmpty()) {
            return null
        }

        val result = mapFor(
            scope,
            hookId,
            create = false,
        )?.remove(key)
        removes.incrementAndGet()
        return result
    }

    fun clear(
        scope: String,
        hookId: String = "",
    ): Int
    {
        val count = mapFor(
            scope,
            hookId,
            create = false,
        )?.clear() ?: 0
        clears.incrementAndGet()
        return count
    }

    fun clearHook(hookId: String): Int
    {
        if (hookId.isEmpty()) {
            return 0
        }

        synchronized(hookLock) {
            val map = hookStates.remove(hookId) ?: return 0
            clears.incrementAndGet()
            return map.clear()
        }
    }

    fun increment(
        scope: String,
        key: String,
        delta: Double,
        hookId: String = "",
    ): Number
    {
        val old = get(scope, key, hookId)
        val oldNumber = when (old) {
            is Number -> old.toDouble()
            null -> 0.0
            else -> old.toString().toDoubleOrNull() ?: 0.0
        }
        val next = oldNumber + delta
        val value: Number = if (
            next % 1.0 == 0.0 &&
            next >= Long.MIN_VALUE.toDouble() &&
            next <= Long.MAX_VALUE.toDouble()
        ) {
            next.toLong()
        } else {
            next
        }
        set(scope, key, value, hookId)
        return value
    }

    fun append(
        scope: String,
        key: String,
        value: Any?,
        hookId: String = "",
    ): List<Any?>
    {
        val current = get(scope, key, hookId)
        val list = mutableListOf<Any?>()
        when (current) {
            is List<*> -> list.addAll(current)
            null -> {
            }
            else -> list.add(current)
        }
        list.add(value)
        while (list.size > maxAppendItems) {
            list.removeAt(0)
        }
        set(scope, key, list, hookId)
        return list
    }

    fun resolve(
        path: String,
        hookId: String = "",
    ): Any?
    {
        val parsed = parseStatePath(path) ?: return ActionExecutor.MISSING
        val scope = parsed.first
        val key = parsed.second
        if (!contains(scope, key, hookId)) {
            return ActionExecutor.MISSING
        }
        return get(scope, key, hookId)
    }

    fun setPath(
        path: String,
        value: Any?,
        hookId: String = "",
    ): Boolean
    {
        val parsed = parseStatePath(path) ?: return false
        set(parsed.first, parsed.second, value, hookId)
        return true
    }

    fun view(hookId: String = ""): Map<String, Any?>
    {
        val hookSnapshot = synchronized(hookLock) {
            hookStates[hookId]?.snapshot() ?: LinkedHashMap()
        }
        val threadSnapshot = threadState.get()?.snapshot()
            ?: LinkedHashMap()

        return linkedMapOf(
            "process" to processState.snapshot(),
            "package" to packageState.snapshot(),
            "hook" to hookSnapshot,
            "thread" to threadSnapshot,
        )
    }

    fun snapshotJson(): JSONObject
    {
        val hooks = JSONObject()
        synchronized(hookLock) {
            for ((hookId, map) in hookStates) {
                hooks.put(
                    hookId,
                    mapSnapshotJson(map),
                )
            }
        }

        return JSONObject().apply {
            put("enabled", true)
            put("package", packageName)
            put("package_scope_process_local", true)
            put("max_keys_per_scope", maxKeysPerScope)
            put("max_hook_scopes", maxHookScopes)
            put("max_append_items", maxAppendItems)
            put("process", mapSnapshotJson(processState))
            put("package_scope", mapSnapshotJson(packageState))
            put("hooks", hooks)
            put(
                "thread_scope",
                JSONObject().apply {
                    put("thread_local", true)
                    put("enumerable", false)
                }
            )
            put(
                "operations",
                JSONObject().apply {
                    put("reads", reads.get())
                    put("writes", writes.get())
                    put("removes", removes.get())
                    put("clears", clears.get())
                }
            )
        }
    }

    private fun mapFor(
        scope: String,
        hookId: String,
        create: Boolean,
    ): BoundedStateMap?
    {
        return when (normalizeScope(scope)) {
            "process" -> processState
            "package" -> packageState
            "thread" -> {
                var map = threadState.get()
                if (map == null && create) {
                    map = BoundedStateMap(maxKeysPerScope)
                    threadState.set(map)
                }
                map
            }
            "hook" -> {
                if (hookId.isEmpty()) {
                    return null
                }
                synchronized(hookLock) {
                    val existing = hookStates[hookId]
                    if (existing != null || !create) {
                        existing
                    } else {
                        val created = BoundedStateMap(
                            maxKeysPerScope
                        )
                        hookStates[hookId] = created
                        created
                    }
                }
            }
            else -> null
        }
    }

    private fun normalizeScope(scope: String): String
    {
        return when (scope.trim().lowercase()) {
            "pkg" -> "package"
            "global" -> "process"
            "" -> "process"
            else -> scope.trim().lowercase()
        }
    }

    private fun parseStatePath(path: String): Pair<String, String>?
    {
        val text = path.trim()
        if (!text.startsWith("state.")) {
            return null
        }
        val rest = text.substring(6)
        val dot = rest.indexOf('.')
        if (dot <= 0 || dot >= rest.length - 1) {
            return null
        }
        val scope = normalizeScope(rest.substring(0, dot))
        if (
            scope != "process" &&
            scope != "package" &&
            scope != "hook" &&
            scope != "thread"
        ) {
            return null
        }
        val key = rest.substring(dot + 1).trim()
        if (key.isEmpty()) {
            return null
        }
        return scope to key
    }

    private fun mapSnapshotJson(map: BoundedStateMap): JSONObject
    {
        val snapshot = map.snapshot()
        val values = JSONObject()
        for ((key, value) in snapshot) {
            values.put(
                key,
                summarizeValue(value),
            )
        }

        return JSONObject().apply {
            put("count", snapshot.size)
            put("values", values)
        }
    }

    private fun summarizeValue(value: Any?): Any
    {
        if (value == null) {
            return JSONObject.NULL
        }
        return when (value) {
            is Boolean,
            is Number -> value

            is CharSequence -> {
                val text = value.toString()
                if (text.length <= 512) {
                    text
                } else {
                    text.substring(0, 512) + "…"
                }
            }

            is Collection<*> -> {
                JSONObject().apply {
                    put("type", value.javaClass.name)
                    put("size", value.size)
                    val preview = JSONArray()
                    for (item in value.take(8)) {
                        preview.put(summarizeValue(item))
                    }
                    put("preview", preview)
                }
            }

            is Map<*, *> -> {
                JSONObject().apply {
                    put("type", value.javaClass.name)
                    put("size", value.size)
                }
            }

            else -> {
                JSONObject().apply {
                    put("type", value.javaClass.name)
                    val text = value.toString()
                    put(
                        "preview",
                        if (text.length <= 256) {
                            text
                        } else {
                            text.substring(0, 256) + "…"
                        },
                    )
                }
            }
        }
    }
}
