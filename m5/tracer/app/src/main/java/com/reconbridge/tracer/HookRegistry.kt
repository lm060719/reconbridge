package com.reconbridge.tracer

import de.robv.android.xposed.XC_MethodHook
import org.json.JSONArray
import org.json.JSONObject
import java.security.MessageDigest
import java.util.LinkedHashMap

internal interface LiveHookHandle
{
    fun unhook()
}

internal class XposedLiveHookHandle(
    private val delegate: XC_MethodHook.Unhook,
) : LiveHookHandle
{
    override fun unhook()
    {
        delegate.unhook()
    }
}

internal data class HookInstallResult(
    val handles: List<LiveHookHandle>,
    val members: List<String>,
)

internal data class HookSyncResult(
    val added: Int,
    val replaced: Int,
    val removed: Int,
    val unchanged: Int,
    val pending: Int,
    val failed: Int,
    val errors: List<String>,
)
{
    fun toJson(): JSONObject
    {
        return JSONObject().apply {
            put("added", added)
            put("replaced", replaced)
            put("removed", removed)
            put("unchanged", unchanged)
            put("pending", pending)
            put("failed", failed)
            put("errors", JSONArray(errors))
        }
    }
}

private data class InstalledHook(
    val id: String,
    val specFingerprint: String,
    val members: List<String>,
    val handles: List<LiveHookHandle>,
    val installedAt: Long,
    val classLoaderId: String,
    val classLoaderClass: String,
)

private data class PendingHook(
    val id: String,
    val specFingerprint: String,
    val spec: JSONObject,
    val className: String,
    val queuedAt: Long,
    val replacingInstalled: Boolean,
    var attempts: Int = 0,
    var lastError: String = "",
)

private data class InstallAttempt(
    val result: HookInstallResult?,
    val loader: TrackedClassLoader?,
    val classNotFoundOnly: Boolean,
    val error: String,
)

/**
 * 目标进程内的 HookRegistry。
 *
 * daemon 下发的 targets 是完整期望状态：
 * - 新 id：在所有已知 ClassLoader 上尝试安装；
 * - 类尚不存在：进入 pending，而不是直接失败；
 * - 新 ClassLoader / 目标类加载：自动重试 pending；
 * - 同 id / spec 改变：新 spec 成功后才卸载旧 hook；
 * - 配置中消失的 id：installed 立即 live unhook，pending 同时移除。
 */
internal class HookRegistry(
    private val packageName: String,
    private val processName: String,
    private val pid: Int,
    initialClassLoader: ClassLoader,
    private val installer: (JSONObject, ClassLoader) -> HookInstallResult,
)
{
    private val lock = Any()
    private val installed = LinkedHashMap<String, InstalledHook>()
    private val pending = LinkedHashMap<String, PendingHook>()
    private val classLoaders = ClassLoaderRegistry(initialClassLoader)
    private var lastSyncAt = 0L
    private var lastPendingResolveAt = 0L

    fun reconcile(targets: JSONArray): HookSyncResult
    {
        synchronized(lock) {
            val desired = LinkedHashMap<String, JSONObject>()

            for (index in 0 until targets.length()) {
                val target = targets.optJSONObject(index) ?: continue
                if (target.optString("kind", "native") != "java") {
                    continue
                }

                val id = target.optString("id", "").trim()
                if (id.isEmpty()) {
                    continue
                }

                desired[id] = JSONObject(target.toString())
            }

            var added = 0
            var replaced = 0
            var removed = 0
            var unchanged = 0
            var failed = 0
            val errors = mutableListOf<String>()

            val removedInstalledIds = installed.keys.filter {
                !desired.containsKey(it)
            }
            for (id in removedInstalledIds) {
                val old = installed.remove(id) ?: continue
                safeUnhook(old)
                removed++
            }

            val removedPendingIds = pending.keys.filter {
                !desired.containsKey(it)
            }
            for (id in removedPendingIds) {
                pending.remove(id)
            }

            for ((id, spec) in desired) {
                val fingerprint = fingerprint(spec)
                val old = installed[id]
                val waiting = pending[id]

                if (waiting != null && waiting.specFingerprint != fingerprint) {
                    pending.remove(id)
                }

                if (old != null && old.specFingerprint == fingerprint) {
                    unchanged++
                    continue
                }

                val currentWaiting = pending[id]
                if (
                    currentWaiting != null &&
                    currentWaiting.specFingerprint == fingerprint
                ) {
                    unchanged++
                    continue
                }

                val attempt = attemptInstallOnKnownLoaders(spec)
                val fresh = attempt.result

                if (
                    fresh != null &&
                    fresh.handles.isNotEmpty() &&
                    attempt.loader != null
                ) {
                    val replacement = installedHook(
                        id = id,
                        fingerprint = fingerprint,
                        result = fresh,
                        loader = attempt.loader,
                    )

                    pending.remove(id)
                    if (old == null) {
                        installed[id] = replacement
                        added++
                    } else {
                        installed[id] = replacement
                        safeUnhook(old)
                        replaced++
                    }
                    continue
                }

                val className = spec.optString("class", "").trim()
                if (className.isNotEmpty() && attempt.classNotFoundOnly) {
                    pending[id] = PendingHook(
                        id = id,
                        specFingerprint = fingerprint,
                        spec = JSONObject(spec.toString()),
                        className = className,
                        queuedAt = System.currentTimeMillis(),
                        replacingInstalled = old != null,
                        attempts = classLoaders.size(),
                        lastError = attempt.error,
                    )
                    continue
                }

                failed++
                errors.add(
                    id + ": " + attempt.error.ifEmpty {
                        "安装结果为空"
                    }
                )
            }

            lastSyncAt = System.currentTimeMillis()
            return HookSyncResult(
                added = added,
                replaced = replaced,
                removed = removed,
                unchanged = unchanged,
                pending = pending.size,
                failed = failed,
                errors = errors,
            )
        }
    }

    fun onLoaderAvailable(
        loader: ClassLoader,
        source: String,
    ): HookSyncResult
    {
        synchronized(lock) {
            classLoaders.register(loader, source)
            return resolvePendingLocked(
                loader = loader,
                loadedClassName = null,
            )
        }
    }

    fun onClassLoaded(
        loader: ClassLoader,
        className: String,
    ): HookSyncResult
    {
        synchronized(lock) {
            classLoaders.register(
                loader = loader,
                source = "ClassLoader.loadClass",
                loadedClass = className,
            )
            return resolvePendingLocked(
                loader = loader,
                loadedClassName = className,
            )
        }
    }

    fun hasPending(): Boolean
    {
        synchronized(lock) {
            return pending.isNotEmpty()
        }
    }

    fun pendingClassNames(): Set<String>
    {
        synchronized(lock) {
            return pending.values.map { it.className }.toSet()
        }
    }

    fun clear(): Int
    {
        synchronized(lock) {
            val count = installed.size
            val rows = installed.values.toList()
            installed.clear()
            pending.clear()
            for (row in rows) {
                safeUnhook(row)
            }
            lastSyncAt = System.currentTimeMillis()
            return count
        }
    }

    fun snapshotJson(): JSONObject
    {
        synchronized(lock) {
            val hooks = JSONArray()
            for ((_, hook) in installed) {
                hooks.put(
                    JSONObject().apply {
                        put("id", hook.id)
                        put("spec_fingerprint", hook.specFingerprint)
                        put("member_count", hook.handles.size)
                        put("members", JSONArray(hook.members))
                        put("installed_at", hook.installedAt)
                        put("class_loader_id", hook.classLoaderId)
                        put("class_loader_class", hook.classLoaderClass)
                        put("state", "installed")
                    }
                )
            }

            val pendingHooks = JSONArray()
            for ((_, hook) in pending) {
                pendingHooks.put(
                    JSONObject().apply {
                        put("id", hook.id)
                        put("spec_fingerprint", hook.specFingerprint)
                        put("class", hook.className)
                        put("queued_at", hook.queuedAt)
                        put("attempts", hook.attempts)
                        put("last_error", hook.lastError)
                        put(
                            "replacing_installed",
                            hook.replacingInstalled,
                        )
                        put("state", "pending_class")
                    }
                )
            }

            return JSONObject().apply {
                put("package", packageName)
                put("process", processName)
                put("pid", pid)
                put("live_unhook", true)
                put("replace_supported", true)
                put("pending_hook_supported", true)
                put("dynamic_classloader_supported", true)
                put("installed_count", installed.size)
                put("pending_count", pending.size)
                put("class_loader_count", classLoaders.size())
                put("last_sync_at", lastSyncAt)
                put("last_pending_resolve_at", lastPendingResolveAt)
                put("hooks", hooks)
                put("pending_hooks", pendingHooks)
                put("class_loaders", classLoaders.snapshotJson())
            }
        }
    }

    private fun resolvePendingLocked(
        loader: ClassLoader,
        loadedClassName: String?,
    ): HookSyncResult
    {
        var added = 0
        var replaced = 0
        var failed = 0
        val errors = mutableListOf<String>()

        val candidates = pending.values.filter { row ->
            loadedClassName == null || row.className == loadedClassName
        }

        for (row in candidates) {
            val tracked = classLoaders.register(
                loader = loader,
                source = if (loadedClassName == null) {
                    "dynamic-loader"
                } else {
                    "ClassLoader.loadClass"
                },
                loadedClass = loadedClassName ?: "",
            )

            row.attempts++
            try {
                val fresh = ClassLoaderWatcher.runSuppressed {
                    installer(
                        JSONObject(row.spec.toString()),
                        loader,
                    )
                }

                if (fresh.handles.isEmpty()) {
                    row.lastError = "安装结果为空"
                    continue
                }

                val replacement = installedHook(
                    id = row.id,
                    fingerprint = row.specFingerprint,
                    result = fresh,
                    loader = tracked,
                )
                val old = installed[row.id]
                installed[row.id] = replacement
                pending.remove(row.id)

                if (old == null) {
                    added++
                } else {
                    safeUnhook(old)
                    replaced++
                }
            } catch (t: Throwable) {
                row.lastError = t.toString()
                if (!isClassNotFound(t)) {
                    failed++
                    errors.add(row.id + ": " + t)
                }
            }
        }

        lastPendingResolveAt = System.currentTimeMillis()
        return HookSyncResult(
            added = added,
            replaced = replaced,
            removed = 0,
            unchanged = 0,
            pending = pending.size,
            failed = failed,
            errors = errors,
        )
    }

    private fun attemptInstallOnKnownLoaders(
        spec: JSONObject,
    ): InstallAttempt
    {
        val loaders = classLoaders.loaders()
        var classNotFoundCount = 0
        var lastError = ""

        for (tracked in loaders) {
            try {
                val result = ClassLoaderWatcher.runSuppressed {
                    installer(
                        JSONObject(spec.toString()),
                        tracked.loader,
                    )
                }
                if (result.handles.isNotEmpty()) {
                    return InstallAttempt(
                        result = result,
                        loader = tracked,
                        classNotFoundOnly = false,
                        error = "",
                    )
                }
                lastError = "安装结果为空"
            } catch (t: Throwable) {
                lastError = t.toString()
                if (isClassNotFound(t)) {
                    classNotFoundCount++
                    continue
                }

                return InstallAttempt(
                    result = null,
                    loader = null,
                    classNotFoundOnly = false,
                    error = lastError,
                )
            }
        }

        return InstallAttempt(
            result = null,
            loader = null,
            classNotFoundOnly = (
                loaders.isNotEmpty() &&
                classNotFoundCount == loaders.size
            ),
            error = lastError,
        )
    }

    private fun installedHook(
        id: String,
        fingerprint: String,
        result: HookInstallResult,
        loader: TrackedClassLoader,
    ): InstalledHook
    {
        return InstalledHook(
            id = id,
            specFingerprint = fingerprint,
            members = result.members,
            handles = result.handles,
            installedAt = System.currentTimeMillis(),
            classLoaderId = loader.id,
            classLoaderClass = loader.className,
        )
    }

    private fun safeUnhook(hook: InstalledHook)
    {
        for (handle in hook.handles.asReversed()) {
            try {
                handle.unhook()
            } catch (_: Throwable) {
            }
        }
    }

    private fun isClassNotFound(t: Throwable?): Boolean
    {
        var current = t
        var depth = 0
        while (current != null && depth < 8) {
            if (
                current is ClassNotFoundException ||
                current is NoClassDefFoundError
            ) {
                return true
            }
            current = current.cause
            depth++
        }
        return false
    }

    companion object
    {
        internal fun fingerprint(value: JSONObject): String
        {
            val canonical = canonicalJson(value)
            val digest = MessageDigest.getInstance("SHA-256")
                .digest(canonical.toByteArray(Charsets.UTF_8))

            return digest.take(12).joinToString("") { byte ->
                "%02x".format(byte.toInt() and 0xff)
            }
        }

        private fun canonicalJson(value: Any?): String
        {
            return when (value) {
                null,
                JSONObject.NULL -> "null"

                is JSONObject -> {
                    val keys = mutableListOf<String>()
                    val iterator = value.keys()
                    while (iterator.hasNext()) {
                        keys.add(iterator.next())
                    }
                    keys.sort()

                    keys.joinToString(
                        prefix = "{",
                        postfix = "}",
                        separator = ",",
                    ) { key ->
                        JSONObject.quote(key) + ":" + canonicalJson(
                            value.opt(key)
                        )
                    }
                }

                is JSONArray -> {
                    (0 until value.length()).joinToString(
                        prefix = "[",
                        postfix = "]",
                        separator = ",",
                    ) { index ->
                        canonicalJson(value.opt(index))
                    }
                }

                is String -> JSONObject.quote(value)
                is Number,
                is Boolean -> value.toString()

                else -> JSONObject.quote(value.toString())
            }
        }
    }
}
