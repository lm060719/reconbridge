package com.reconbridge.tracer

import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XposedBridge

/**
 * 监听 Android 动态 ClassLoader。
 *
 * 两层策略：
 * 1. 常驻监听 BaseDexClassLoader 构造函数，低频地发现 Path/Dex/InMemoryDexClassLoader；
 * 2. 只有存在 pending hook 时才临时监听 ClassLoader.loadClass，捕获自定义 loader。
 *
 * loadClass watcher 使用 ThreadLocal 递归保护；HookRegistry 主动尝试 loader.loadClass 时也通过
 * runSuppressed 包裹，避免“安装 hook -> loadClass -> watcher -> 再安装”的递归。
 */
internal class ClassLoaderWatcher(
    private val onLoaderAvailable: (ClassLoader, String) -> Unit,
    private val onClassLoaded: (ClassLoader, String) -> Unit,
)
{
    private val lock = Any()
    private val constructorHandles = mutableListOf<LiveHookHandle>()
    private val loadClassHandles = mutableListOf<LiveHookHandle>()

    fun start()
    {
        synchronized(lock) {
            if (constructorHandles.isNotEmpty()) {
                return
            }

            try {
                val baseDex = Class.forName("dalvik.system.BaseDexClassLoader")
                val callback = object : XC_MethodHook()
                {
                    override fun afterHookedMethod(param: MethodHookParam)
                    {
                        if (isSuppressed()) {
                            return
                        }
                        val loader = param.thisObject as? ClassLoader ?: return
                        runSuppressed {
                            onLoaderAvailable(
                                loader,
                                "BaseDexClassLoader.<init>",
                            )
                        }
                    }
                }

                constructorHandles.addAll(
                    XposedBridge.hookAllConstructors(baseDex, callback)
                        .map { XposedLiveHookHandle(it) }
                )
            } catch (_: Throwable) {
                // 某些 ROM 隐藏/裁剪 BaseDexClassLoader 时仍可依赖 pending loadClass watcher。
            }
        }
    }

    fun setPendingEnabled(enabled: Boolean)
    {
        synchronized(lock) {
            if (enabled) {
                ensureLoadClassWatcherLocked()
            } else {
                clearHandles(loadClassHandles)
            }
        }
    }

    fun snapshotJson(): JSONObject
    {
        synchronized(lock) {
            return JSONObject().apply {
                put(
                    "base_dex_constructor_watch",
                    constructorHandles.isNotEmpty(),
                )
                put(
                    "load_class_watch",
                    loadClassHandles.isNotEmpty(),
                )
            }
        }
    }

    fun close()
    {
        synchronized(lock) {
            clearHandles(loadClassHandles)
            clearHandles(constructorHandles)
        }
    }

    private fun ensureLoadClassWatcherLocked()
    {
        if (loadClassHandles.isNotEmpty()) {
            return
        }

        val callback = object : XC_MethodHook()
        {
            override fun afterHookedMethod(param: MethodHookParam)
            {
                if (isSuppressed()) {
                    return
                }

                val loader = param.thisObject as? ClassLoader ?: return
                val loaded = param.result as? Class<*> ?: return
                val requested = param.args.firstOrNull() as? String
                val className = loaded.name.ifEmpty {
                    requested ?: return
                }

                runSuppressed {
                    onClassLoaded(loader, className)
                }
            }
        }

        loadClassHandles.addAll(
            XposedBridge.hookAllMethods(
                ClassLoader::class.java,
                "loadClass",
                callback,
            ).map { XposedLiveHookHandle(it) }
        )
    }

    private fun clearHandles(handles: MutableList<LiveHookHandle>)
    {
        for (handle in handles.asReversed()) {
            try {
                handle.unhook()
            } catch (_: Throwable) {
            }
        }
        handles.clear()
    }

    companion object
    {
        private val suppressed = ThreadLocal<Boolean>()

        internal fun isSuppressed(): Boolean
        {
            return suppressed.get() == true
        }

        internal fun <T> runSuppressed(block: () -> T): T
        {
            val previous = suppressed.get() == true
            suppressed.set(true)
            return try {
                block()
            } finally {
                if (previous) {
                    suppressed.set(true)
                } else {
                    suppressed.remove()
                }
            }
        }
    }
}
