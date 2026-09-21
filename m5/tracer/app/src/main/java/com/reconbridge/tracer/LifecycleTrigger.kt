package com.reconbridge.tracer

import org.json.JSONObject

/**
 * on_lifecycle 的纯解析/过滤逻辑。
 *
 * 保持为 Android 无关代码，便于 JVM 单元测试。
 */
internal object LifecycleTrigger
{
    fun normalizeEventName(raw: String): String
    {
        val value = raw.trim()
        require(value.isNotEmpty()) {
            "on_lifecycle stage/event/name 不能为空"
        }

        if (value.startsWith("lifecycle.")) {
            return value
        }

        if (value == "application_attached") {
            return "lifecycle.application_attached"
        }

        if (value.startsWith("activity_")) {
            return "lifecycle." + value
        }

        return when (value) {
            "created",
            "started",
            "resumed",
            "paused",
            "stopped",
            "save_instance_state",
            "destroyed" -> "lifecycle.activity_" + value

            else -> "lifecycle." + value
        }
    }

    fun normalizeHandler(handler: JSONObject): JSONObject
    {
        val copy = JSONObject(handler.toString())
        val raw = copy.optString(
            "stage",
            copy.optString(
                "event",
                copy.optString("name"),
            ),
        )
        copy.put(
            "name",
            normalizeEventName(raw),
        )
        copy.put("_recon_lifecycle_trigger", true)
        return copy
    }

    fun matches(
        handler: JSONObject,
        event: RuntimeEvent,
    ): Boolean
    {
        if (!handler.optBoolean("_recon_lifecycle_trigger", false)) {
            return true
        }

        val map = event.asMap()
        val actualClass = map["activity_class"]?.toString().orEmpty()

        val exact = handler.optString(
            "activity",
            handler.optString("activity_class"),
        ).trim()

        if (exact.isNotEmpty()) {
            val simple = actualClass.substringAfterLast('.')
            if (actualClass != exact && simple != exact) {
                return false
            }
        }

        val regex = handler.optString("activity_match").trim()
        if (regex.isNotEmpty()) {
            val matched = try {
                Regex(regex).containsMatchIn(actualClass)
            } catch (_: Throwable) {
                false
            }
            if (!matched) {
                return false
            }
        }

        return true
    }
}
