package com.reconbridge.tracer

import org.json.JSONArray
import org.json.JSONObject
import java.util.IdentityHashMap
import java.util.LinkedHashMap

internal data class TrackedClassLoader(
    val id: String,
    val loader: ClassLoader,
    val className: String,
    val source: String,
    val firstSeenAt: Long,
    var lastSeenAt: Long,
    var lastLoadedClass: String = "",
)

/**
 * 目标进程内的 ClassLoader 注册表。
 *
 * 使用对象身份而不是 equals/hashCode 区分 loader，避免插件框架自定义 equals 导致误合并。
 * Phase 2 只保存轻量元数据与 loader 强引用；生命周期与 App 进程一致。
 */
internal class ClassLoaderRegistry(
    initialLoader: ClassLoader,
)
{
    private val lock = Any()
    private val byIdentity = IdentityHashMap<ClassLoader, TrackedClassLoader>()
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
            val now = System.currentTimeMillis()
            val existing = byIdentity[loader]
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
            byIdentity[loader] = row
            ordered[row.id] = row
            return row
        }
    }

    fun idOf(loader: ClassLoader): String
    {
        synchronized(lock) {
            return byIdentity[loader]?.id
                ?: register(loader, "late-register").id
        }
    }

    fun loaders(): List<TrackedClassLoader>
    {
        synchronized(lock) {
            return ordered.values.toList()
        }
    }

    fun size(): Int
    {
        synchronized(lock) {
            return ordered.size
        }
    }

    fun snapshotJson(): JSONArray
    {
        synchronized(lock) {
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
                    }
                )
            }
            return out
        }
    }
}
