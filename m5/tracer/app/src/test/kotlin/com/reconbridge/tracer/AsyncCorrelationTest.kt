package com.reconbridge.tracer

import org.junit.Assert.*
import org.junit.Test

class AsyncCorrelationTest {
    @Test fun linksSameObjectAcrossThreadsWithoutEqualsCollision() {
        val links = AsyncTaskLinks()
        val task = String(charArrayOf('a'))
        links.enqueue(task, "tasks", "parent")
        assertEquals("unmatched", links.execute(String(charArrayOf('a')), "tasks").getString("status"))
        var result = ""
        val thread = Thread { result = links.execute(task, "tasks").getString("enqueue_span_id") }
        thread.start(); thread.join()
        assertEquals("parent", result)
        assertEquals("unmatched", links.execute(task, "tasks").getString("status"))
    }
    @Test fun duplicateSubmissionsRemainAmbiguousForEveryExecution() {
        val links = AsyncTaskLinks(); val task = Any()
        links.enqueue(task,"tasks","one"); links.enqueue(task,"tasks","two")
        repeat(2) {
            val result = links.execute(task,"tasks")
            assertEquals("ambiguous",result.getString("status"))
            assertTrue(result.isNull("enqueue_span_id"))
        }
    }
    @Test fun expirationCapacityCancellationAndNamespacesAreExplicit() {
        var now = 0L
        val links = AsyncTaskLinks(capacity=1,ttlNanos=10,clock={ now })
        val one = Any(); val two = Any()
        links.enqueue(one,"a","one")
        assertEquals("unmatched",links.execute(one,"b").getString("status"))
        val queued = links.enqueue(two,"a","two")
        assertEquals(1,queued.getInt("evicted_total"))
        assertEquals("unmatched",links.execute(one,"a").getString("status"))
        links.cancel(queued.getString("task_id"))
        assertEquals("unmatched",links.execute(two,"a").getString("status"))
        links.enqueue(one,"a","one"); now = 11
        assertEquals("unmatched",links.execute(one,"a").getString("status"))
    }
    @Test fun spanContextIsNestedAndThreadLocalAndCleaned() {
        val first = TraceCorrelation.begin(); val second = TraceCorrelation.begin()
        assertEquals(first.getString("span_id"),second.getString("parent_span_id"))
        var parentIsNull = false
        val thread = Thread {
            val isolated = TraceCorrelation.begin(); parentIsNull=isolated.isNull("parent_span_id")
            TraceCorrelation.end(isolated.getString("span_id"))
        }
        thread.start();thread.join(); assertTrue(parentIsNull)
        TraceCorrelation.end(second.getString("span_id"));TraceCorrelation.end(first.getString("span_id"))
        val next=TraceCorrelation.begin();assertTrue(next.isNull("parent_span_id"));TraceCorrelation.end(next.getString("span_id"))
    }
}
