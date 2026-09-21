package com.reconbridge.tracer

import de.robv.android.xposed.XC_MethodHook
import org.json.JSONArray
import org.json.JSONObject
import java.security.MessageDigest
import java.util.LinkedHashMap

/**
 * 一个已由 LSPosed 安装的 live hook handle。
 *
 * 把 Xposed 的具体 Unhook 类型包在接口后面，便于 JVM 单元测试用 fake handle
 * 验证 add/remove/replace，而不需要真的启动 LSPosed。
 */
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
)

/**
 * 目标进程内的 HookRegistry。
 *
 * 它把 daemon 下发的 targets 当作“期望状态”，每次 reconcile：
 *  - 新 id：安装
 *  - 同 id / 同 spec：保持
 *  - 同 id / spec 改变：先安装新 hook，成功后再 live unhook 旧 hook
 *  - 配置里消失的 id：立即 live unhook
 *
 * 因此 daemon 仍然只需要同步一份完整配置，不必额外维护复杂增量状态。
 */
internal class HookRegistry(
    private val packageName: String,
    private val processName: String,
    private val pid: Int,
    private val installer: (JSONObject) -> HookInstallResult,
)
{
    private val lock = Any()
    private val installed = LinkedHashMap<String, InstalledHook>()
    private var lastSyncAt = 0L

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

                // 同一批配置里 id 重复时以后者为准，和 daemon append replace 语义一致。
                desired[id] = JSONObject(target.toString())
            }

            var added = 0
            var replaced = 0
            var removed = 0
            var unchanged = 0
            var failed = 0
            val errors = mutableListOf<String>()

            val removedIds = installed.keys.filter { !desired.containsKey(it) }
            for (id in removedIds) {
                val old = installed.remove(id) ?: continue
                safeUnhook(old)
                removed++
            }

            for ((id, spec) in desired) {
                val fingerprint = fingerprint(spec)
                val old = installed[id]

                if (old != null && old.specFingerprint == fingerprint) {
                    unchanged++
                    continue
                }

                try {
                    val fresh = installer(spec)
                    if (fresh.handles.isEmpty()) {
                        failed++
                        errors.add("$id: 安装结果为空")
                        continue
                    }

                    val replacement = InstalledHook(
                        id = id,
                        specFingerprint = fingerprint,
                        members = fresh.members,
                        handles = fresh.handles,
                        installedAt = System.currentTimeMillis(),
                    )

                    if (old == null) {
                        installed[id] = replacement
                        added++
                    } else {
                        // 先确保新 hook 已成功，再卸载旧 hook，避免 replace 失败导致已有能力消失。
                        installed[id] = replacement
                        safeUnhook(old)
                        replaced++
                    }
                } catch (t: Throwable) {
                    failed++
                    errors.add("$id: $t")
                }
            }

            lastSyncAt = System.currentTimeMillis()
            return HookSyncResult(
                added = added,
                replaced = replaced,
                removed = removed,
                unchanged = unchanged,
                failed = failed,
                errors = errors,
            )
        }
    }

    fun clear(): Int
    {
        synchronized(lock) {
            val count = installed.size
            val rows = installed.values.toList()
            installed.clear()
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
                        put("state", "installed")
                    }
                )
            }

            return JSONObject().apply {
                put("package", packageName)
                put("process", processName)
                put("pid", pid)
                put("live_unhook", true)
                put("replace_supported", true)
                put("installed_count", installed.size)
                put("last_sync_at", lastSyncAt)
                put("hooks", hooks)
            }
        }
    }

    private fun safeUnhook(hook: InstalledHook)
    {
        for (handle in hook.handles.asReversed()) {
            try {
                handle.unhook()
            } catch (_: Throwable) {
                // 单个 handle 卸载失败不能阻止其它 handle 继续卸载。
            }
        }
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
                        JSONObject.quote(key) + ":" + canonicalJson(value.opt(key))
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
