package com.reconbridge.tracer

import android.app.Activity
import android.app.Application
import android.content.Context
import org.json.JSONObject
import java.lang.ref.WeakReference
import java.util.LinkedHashMap
import java.util.concurrent.atomic.AtomicLong

/**
 * ActionExecutor 只依赖这个轻量接口，因此 JVM 单元测试可以使用 fake provider，
 * 不需要真的创建 Android Activity/Application。
 */
internal interface RuntimeContextProvider
{
    fun applicationObject(): Any?
    fun contextObject(): Any?
    fun activityObject(): Any?
    fun lifecycleView(): Map<String, Any?>
    fun snapshotJson(): JSONObject
}

/**
 * 进程级 Context / Activity 注册表。
 *
 * Activity 始终使用 WeakReference，避免 Tracer 自己延长页面生命周期。
 * Application/Context 也使用弱引用；真实 Android 进程本身会持有它们。
 */
internal class ContextRegistry(
    private val packageName: String,
    private val processName: String,
) : RuntimeContextProvider
{
    private val lock = Any()

    @Volatile
    private var applicationRef: WeakReference<Application>? = null

    @Volatile
    private var appContextRef: WeakReference<Context>? = null

    @Volatile
    private var activityRef: WeakReference<Activity>? = null

    @Volatile
    private var activityClass: String = ""

    @Volatile
    private var activityState: String = ""

    @Volatile
    private var lastEvent: String = ""

    @Volatile
    private var lastEventAt: Long = 0L

    private val lifecycleCounts = LinkedHashMap<String, AtomicLong>()

    fun recordApplication(
        application: Application,
        context: Context? = null,
        source: String = "application",
    )
    {
        synchronized(lock) {
            applicationRef = WeakReference(application)

            val appContext = try {
                context?.applicationContext
                    ?: application.applicationContext
                    ?: context
                    ?: application
            } catch (_: Throwable) {
                context ?: application
            }

            appContextRef = WeakReference(appContext)
            lastEvent = "application_attached"
            lastEventAt = System.currentTimeMillis()
            incrementLocked("application_attached")
            incrementLocked("application_source_" + source)
        }
    }

    fun recordActivity(
        activity: Activity,
        state: String,
    )
    {
        synchronized(lock) {
            activityRef = WeakReference(activity)
            activityClass = activity.javaClass.name
            activityState = state
            lastEvent = "activity_" + state
            lastEventAt = System.currentTimeMillis()
            incrementLocked("activity_" + state)
        }
    }

    fun clearActivityIfSame(
        activity: Activity,
        state: String = "destroyed",
    )
    {
        synchronized(lock) {
            val current = activityRef?.get()
            if (current === activity) {
                activityRef?.clear()
                activityRef = null
                activityState = state
            }
            activityClass = if (current === activity) {
                activity.javaClass.name
            } else {
                activityClass
            }
            lastEvent = "activity_" + state
            lastEventAt = System.currentTimeMillis()
            incrementLocked("activity_" + state)
        }
    }

    override fun applicationObject(): Any?
    {
        return applicationRef?.get()
    }

    override fun activityObject(): Any?
    {
        val activity = activityRef?.get()
        if (activity == null) {
            activityRef = null
        }
        return activity
    }

    override fun contextObject(): Any?
    {
        return activityObject()
            ?: appContextRef?.get()
            ?: applicationRef?.get()
    }

    override fun lifecycleView(): Map<String, Any?>
    {
        val app = applicationObject()
        val activity = activityObject()
        val context = contextObject()

        return linkedMapOf(
            "application" to app,
            "context" to context,
            "activity" to activity,
            "activity_class" to activityClass,
            "activity_state" to activityState,
            "has_activity" to (activity != null),
            "last_event" to lastEvent,
            "last_event_at" to lastEventAt,
            "package" to packageName,
            "process" to processName,
        )
    }

    override fun snapshotJson(): JSONObject
    {
        val activity = activityObject()
        val application = applicationObject()
        val context = contextObject()

        val counts = JSONObject()
        synchronized(lock) {
            for ((name, counter) in lifecycleCounts) {
                counts.put(name, counter.get())
            }
        }

        return JSONObject().apply {
            put("enabled", true)
            put("package", packageName)
            put("process", processName)
            put("application_available", application != null)
            put(
                "application_class",
                application?.javaClass?.name ?: JSONObject.NULL,
            )
            put("context_available", context != null)
            put(
                "context_class",
                context?.javaClass?.name ?: JSONObject.NULL,
            )
            put("activity_available", activity != null)
            put(
                "activity_class",
                if (activityClass.isEmpty()) {
                    JSONObject.NULL
                } else {
                    activityClass
                },
            )
            put(
                "activity_state",
                if (activityState.isEmpty()) {
                    JSONObject.NULL
                } else {
                    activityState
                },
            )
            put(
                "last_event",
                if (lastEvent.isEmpty()) {
                    JSONObject.NULL
                } else {
                    lastEvent
                },
            )
            put("last_event_at", lastEventAt)
            put("activity_weak_reference", true)
            put("counts", counts)
        }
    }

    private fun incrementLocked(name: String)
    {
        val counter = lifecycleCounts.getOrPut(name) {
            AtomicLong()
        }
        counter.incrementAndGet()
    }
}
