package com.reconbridge.tracer

import org.json.JSONArray
import org.json.JSONObject
import java.lang.ref.WeakReference
import java.util.LinkedHashMap

internal class TrackedClassLoader(
    val id: String,
    loader: ClassLoader,
    val className: String,
    val source: String,
    val firstSeenAt: Long,
    var lastSeenAt: Long,
    var lastLoadedClass: String = "",
)
{
    private val reference = WeakReference(loader)

    fun loaderOrNull(): ClassLoader?
    {
        return reference.get()
    }
}

/**
 * 目标进程内的 ClassLoader 注册表。
 *
 * 以对象身份（===）区分 loader，并使用 WeakReference 保存实例，避免 Tracer 因为
 * “曾经见过某个插件 ClassLoader”就阻止它被 GC。runtime status 只保留轻量元数据。
 */
internal class ClassLoaderRegistry(
    initialLoader: ClassLoader,
)
{
    private val lock = Any()
    private val ordered = LinkedHashMap<String, TrackedClassLoader>()
    private var nextId = 1

    init
    {
        register(
            loader = initialLoader,
            source = "lpparam.classLoader",
            loadedClass = "",
        )
    }

    fun register(
        loader: ClassLoader,
        source: String,
        loadedClass: String = "",
    ): TrackedClassLoader
    {
        synchronized(lock) {
            cleanupLocked()
            val now = System.currentTimeMillis()
            val existing = ordered.values.firstOrNull { row ->
                row.loaderOrNull() === loader
            }
            if (existing != null) {
                existing.lastSeenAt = now
                if (loadedClass.isNotEmpty()) {
                    existing.lastLoadedClass = loadedClass
                }
                return existing
            }

            val row = TrackedClassLoader(
                id = "cl" + nextId++,
                loader = loader,
                className = loader.javaClass.name,
                source = source,
                firstSeenAt = now,
                lastSeenAt = now,
                lastLoadedClass = loadedClass,
            )
            ordered[row.id] = row
            return row
        }
    }

    fun idOf(loader: ClassLoader): String
    {
        synchronized(lock) {
            cleanupLocked()
            return ordered.values.firstOrNull {
                it.loaderOrNull() === loader
            }?.id ?: register(loader, "late-register").id
        }
    }

    fun loaders(): List<TrackedClassLoader>
    {
        synchronized(lock) {
            cleanupLocked()
            return ordered.values.toList()
        }
    }

    fun size(): Int
    {
        synchronized(lock) {
            cleanupLocked()
            return ordered.size
        }
    }

    fun snapshotJson(): JSONArray
    {
        synchronized(lock) {
            cleanupLocked()
            val out = JSONArray()
            for (row in ordered.values) {
                out.put(
                    JSONObject().apply {
                        put("id", row.id)
                        put("class", row.className)
                        put("source", row.source)
                        put("first_seen_at", row.firstSeenAt)
                        put("last_seen_at", row.lastSeenAt)
                        put("last_loaded_class", row.lastLoadedClass)
                        put("alive", row.loaderOrNull() != null)
                    }
                )
            }
            return out
        }
    }

    private fun cleanupLocked()
    {
        val dead = ordered.entries
            .filter { it.value.loaderOrNull() == null }
            .map { it.key }

        for (id in dead) {
            ordered.remove(id)
        }
    }
}
