package com.reconbridge.tracer

import java.lang.ref.WeakReference
import java.util.UUID
import java.util.concurrent.atomic.AtomicLong
import org.json.JSONObject

/** Opt-in task identity observations; never wraps tasks or changes scheduling. */
class AsyncTaskLinks(
    private val capacity: Int = 2048,
    private val ttlNanos: Long = 60_000_000_000L,
    private val clock: () -> Long = System::nanoTime,
) {
    private data class Pending(val task: WeakReference<Any>, val namespace: String,
        val ticket: String, val span: String, val time: Long, var ambiguous: Boolean = false)
    private val pending = mutableListOf<Pending>()
    private var evicted = 0L
    private fun expire() {
        val now = clock()
        pending.removeAll { it.task.get() == null || now - it.time > ttlNanos }
    }
    @Synchronized fun enqueue(task: Any?, namespace: String, span: String): JSONObject {
        expire()
        if (task == null) return JSONObject().put("status", "missing_task")
        val duplicates = pending.filter { it.namespace == namespace && it.task.get() === task }
        duplicates.forEach { it.ambiguous = true }
        if (pending.size >= capacity) { pending.removeAt(0); evicted++ }
        val entry = Pending(WeakReference(task), namespace, UUID.randomUUID().toString(), span, clock(), duplicates.isNotEmpty())
        pending.add(entry)
        return JSONObject().put("status", "enqueued").put("task_id", entry.ticket)
            .put("namespace", namespace).put("ambiguous", entry.ambiguous).put("evicted_total", evicted)
    }
    @Synchronized fun execute(task: Any?, namespace: String): JSONObject {
        expire()
        val index = pending.indexOfFirst { task != null && it.namespace == namespace && it.task.get() === task }
        if (index < 0) return JSONObject().put("status", "unmatched").put("namespace", namespace).put("evicted_total", evicted)
        val entry = pending.removeAt(index)
        return JSONObject().put("status", if (entry.ambiguous) "ambiguous" else "matched")
            .put("namespace", namespace).put("task_id", entry.ticket)
            .put("enqueue_span_id", if (entry.ambiguous) JSONObject.NULL else entry.span)
            .put("evicted_total", evicted)
    }
    @Synchronized fun cancel(ticket: String) { pending.removeAll { it.ticket == ticket } }
}

object TraceCorrelation {
    val processInstance: String = UUID.randomUUID().toString()
    val tasks = AsyncTaskLinks()
    private val counter = AtomicLong()
    private val stack = ThreadLocal.withInitial { mutableListOf<String>() }
    fun begin(): JSONObject {
        val frames = stack.get()
        val span = counter.incrementAndGet().toString()
        val data = JSONObject().put("version", 1).put("span_id", span)
            .put("parent_span_id", frames.lastOrNull() ?: JSONObject.NULL)
            .put("started_ns", System.nanoTime())
        frames.add(span)
        return data
    }
    fun end(span: String) {
        val frames = stack.get()
        frames.remove(span)
        if (frames.isEmpty()) stack.remove()
    }
}
