package com.reconbridge.tracer

import android.app.Activity
import android.app.Application
import android.content.Context
import android.os.Bundle
import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XposedBridge
import org.json.JSONObject
import java.lang.ref.WeakReference
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * Phase 4 Lifecycle Runtime。
 *
 * 只 Hook Application.attach() 一次；获得 Application 后注册官方
 * ActivityLifecycleCallbacks，避免逐个 Hook Activity 子类生命周期方法。
 */
internal class LifecycleManager(
    private val packageName: String,
    private val contextRegistry: ContextRegistry,
    private val eventBus: RuntimeEventBus,
)
{
    private val lock = Any()
    private val hookHandles = mutableListOf<LiveHookHandle>()
    private var callbacksRegistered = false
    private var registeredApplication = WeakReference<Application>(null)
    private val lifecycleEvents = AtomicLong()
    private val attachEvents = AtomicLong()
    private val statusPublishScheduled = AtomicBoolean(false)
    private val statusGeneration = AtomicLong()

    @Volatile
    private var statusPublisher: (() -> Unit)? = null

    private val callbacks = object : Application.ActivityLifecycleCallbacks
    {
        override fun onActivityCreated(
            activity: Activity,
            savedInstanceState: Bundle?,
        )
        {
            onActivity(
                activity,
                "created",
                mapOf(
                    "saved_state_present" to (savedInstanceState != null),
                ),
            )
        }

        override fun onActivityStarted(activity: Activity)
        {
            onActivity(activity, "started")
        }

        override fun onActivityResumed(activity: Activity)
        {
            onActivity(activity, "resumed")
        }

        override fun onActivityPaused(activity: Activity)
        {
            onActivity(activity, "paused")
        }

        override fun onActivityStopped(activity: Activity)
        {
            onActivity(activity, "stopped")
        }

        override fun onActivitySaveInstanceState(
            activity: Activity,
            outState: Bundle,
        )
        {
            onActivity(
                activity,
                "save_instance_state",
                mapOf(
                    "bundle_size" to try {
                        outState.size()
                    } catch (_: Throwable) {
                        -1
                    },
                ),
            )
        }

        override fun onActivityDestroyed(activity: Activity)
        {
            contextRegistry.clearActivityIfSame(
                activity,
                "destroyed",
            )
            emitLifecycleEvent(
                name = "activity_destroyed",
                activity = activity,
            )
        }
    }

    fun setStatusPublisher(publisher: (() -> Unit)?)
    {
        statusPublisher = publisher
    }

    fun start(): Int
    {
        synchronized(lock) {
            if (hookHandles.isNotEmpty()) {
                return hookHandles.size
            }

            attachCurrentApplicationIfAvailable()

            val callback = object : XC_MethodHook()
            {
                override fun afterHookedMethod(param: MethodHookParam)
                {
                    val application = param.thisObject as? Application
                        ?: return
                    val context = param.args.firstOrNull() as? Context

                    attachEvents.incrementAndGet()
                    attachApplication(
                        application,
                        context,
                        "Application.attach",
                    )
                }
            }

            try {
                hookHandles.addAll(
                    XposedBridge.hookAllMethods(
                        Application::class.java,
                        "attach",
                        callback,
                    ).map { XposedLiveHookHandle(it) }
                )
            } catch (_: Throwable) {
                // currentApplication fallback 仍可能已经拿到 Application。
            }

            return hookHandles.size
        }
    }

    fun close()
    {
        synchronized(lock) {
            val application = registeredApplication.get()
            if (application != null && callbacksRegistered) {
                try {
                    application.unregisterActivityLifecycleCallbacks(
                        callbacks
                    )
                } catch (_: Throwable) {
                }
            }
            callbacksRegistered = false
            registeredApplication.clear()

            for (handle in hookHandles.asReversed()) {
                try {
                    handle.unhook()
                } catch (_: Throwable) {
                }
            }
            hookHandles.clear()
        }
    }

    fun snapshotJson(): JSONObject
    {
        synchronized(lock) {
            return JSONObject().apply {
                put("enabled", true)
                put("attach_hook_count", hookHandles.size)
                put(
                    "callbacks_registered",
                    callbacksRegistered,
                )
                put(
                    "registered_application_alive",
                    registeredApplication.get() != null,
                )
                put(
                    "application_attach_events",
                    attachEvents.get(),
                )
                put(
                    "lifecycle_events",
                    lifecycleEvents.get(),
                )
                put(
                    "event_prefix",
                    "lifecycle.",
                )
            }
        }
    }

    private fun attachCurrentApplicationIfAvailable()
    {
        try {
            val activityThread = Class.forName(
                "android.app.ActivityThread"
            )
            val method = activityThread.getDeclaredMethod(
                "currentApplication"
            )
            method.isAccessible = true
            val application = method.invoke(null) as? Application
                ?: return

            attachApplication(
                application,
                application.applicationContext,
                "ActivityThread.currentApplication",
            )
        } catch (_: Throwable) {
        }
    }

    private fun attachApplication(
        application: Application,
        context: Context?,
        source: String,
    )
    {
        synchronized(lock) {
            contextRegistry.recordApplication(
                application,
                context,
                source,
            )

            val current = registeredApplication.get()
            if (current !== application) {
                if (current != null && callbacksRegistered) {
                    try {
                        current.unregisterActivityLifecycleCallbacks(
                            callbacks
                        )
                    } catch (_: Throwable) {
                    }
                }

                try {
                    application.registerActivityLifecycleCallbacks(
                        callbacks
                    )
                    registeredApplication = WeakReference(application)
                    callbacksRegistered = true
                } catch (_: Throwable) {
                    callbacksRegistered = false
                }
            }
        }

        eventBus.emit(
            RuntimeEvent(
                name = "lifecycle.application_attached",
                payload = linkedMapOf(
                    "application" to application,
                    "context" to (
                        context
                            ?: try {
                                application.applicationContext
                            } catch (_: Throwable) {
                                application
                            }
                    ),
                    "application_class" to application.javaClass.name,
                    "source" to source,
                    "package" to packageName,
                ),
                sourceHookId = "__lifecycle__",
            )
        )
        notifyStatusChanged()
    }

    private fun onActivity(
        activity: Activity,
        state: String,
        extra: Map<String, Any?> = emptyMap(),
    )
    {
        contextRegistry.recordActivity(
            activity,
            state,
        )
        emitLifecycleEvent(
            name = "activity_" + state,
            activity = activity,
            extra = extra,
        )
    }

    private fun emitLifecycleEvent(
        name: String,
        activity: Activity,
        extra: Map<String, Any?> = emptyMap(),
    )
    {
        lifecycleEvents.incrementAndGet()

        val payload = LinkedHashMap<String, Any?>()
        payload["activity"] = activity
        payload["activity_class"] = activity.javaClass.name
        payload["context"] = activity
        payload["application"] = try {
            activity.application
        } catch (_: Throwable) {
            contextRegistry.applicationObject()
        }
        payload["state"] = name.removePrefix("activity_")
        payload["package"] = packageName
        for ((key, value) in extra) {
            payload[key] = value
        }

        eventBus.emit(
            RuntimeEvent(
                name = "lifecycle." + name,
                payload = payload,
                sourceHookId = "__lifecycle__",
            )
        )
        notifyStatusChanged()
    }

    private fun notifyStatusChanged()
    {
        statusGeneration.incrementAndGet()
        if (!statusPublishScheduled.compareAndSet(false, true)) {
            return
        }

        Thread({
            try {
                while (true) {
                    val generation = statusGeneration.get()
                    try {
                        Thread.sleep(120)
                    } catch (_: InterruptedException) {
                    }

                    try {
                        statusPublisher?.invoke()
                    } catch (_: Throwable) {
                    }

                    if (statusGeneration.get() == generation) {
                        break
                    }
                }
            } finally {
                statusPublishScheduled.set(false)

                // 防止最后一次检查与 scheduled=false 之间刚好又有生命周期事件。
                val generation = statusGeneration.get()
                try {
                    Thread.sleep(1)
                } catch (_: InterruptedException) {
                }
                if (
                    statusGeneration.get() != generation &&
                    statusPublisher != null
                ) {
                    notifyStatusChanged()
                }
            }
        }, "ReconTracer-lifecycle-status").apply {
            isDaemon = true
            start()
        }
    }
}
