package com.reconbridge.tracer

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ClassLoaderRegistryTest
{
    @Test
    fun registryUsesIdentityAndKeepsStableIds()
    {
        val first = object : ClassLoader(null) {}
        val second = object : ClassLoader(null) {}
        val registry = ClassLoaderRegistry(first)

        val firstAgain = registry.register(
            first,
            "repeat",
            "com.example.First",
        )
        val secondRow = registry.register(
            second,
            "DexClassLoader.<init>",
            "com.example.Second",
        )

        assertEquals("cl1", firstAgain.id)
        assertEquals("cl2", secondRow.id)
        assertNotEquals(firstAgain.id, secondRow.id)
        assertEquals(2, registry.size())
        assertEquals(
            "com.example.First",
            firstAgain.lastLoadedClass,
        )
    }

    @Test
    fun snapshotContainsLoaderMetadata()
    {
        val loader = object : ClassLoader(null) {}
        val registry = ClassLoaderRegistry(loader)

        registry.register(
            loader,
            "ClassLoader.loadClass",
            "plugin.Target",
        )

        val snapshot = registry.snapshotJson()

        assertEquals(1, snapshot.length())
        val row = snapshot.getJSONObject(0)
        assertEquals("cl1", row.getString("id"))
        assertTrue(row.getString("class").isNotEmpty())
        assertEquals(
            "plugin.Target",
            row.getString("last_loaded_class"),
        )
    }
}
