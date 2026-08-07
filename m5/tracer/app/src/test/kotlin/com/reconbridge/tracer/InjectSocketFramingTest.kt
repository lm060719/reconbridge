package com.reconbridge.tracer

import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.EOFException
import java.io.InputStream

class InjectSocketFramingTest {

    private fun le32(v: Int): ByteArray = byteArrayOf(
        (v and 0xff).toByte(),
        ((v ushr 8) and 0xff).toByte(),
        ((v ushr 16) and 0xff).toByte(),
        ((v ushr 24) and 0xff).toByte(),
    )

    private fun readLe32(input: InputStream): Int {
        val b = ByteArray(4)
        readFully(input, b)
        return (b[0].toInt() and 0xff) or
            ((b[1].toInt() and 0xff) shl 8) or
            ((b[2].toInt() and 0xff) shl 16) or
            ((b[3].toInt() and 0xff) shl 24)
    }

    private fun readFully(input: InputStream, buf: ByteArray) {
        var off = 0
        while (off < buf.size) {
            val n = input.read(buf, off, buf.size - off)
            if (n <= 0) throw EOFException()
            off += n
        }
    }

    @Test
    fun testLe32EncodingAndDecoding() {
        val testValues = intArrayOf(0, 1, 255, 65535, 0x12345678, -1, Int.MAX_VALUE, Int.MIN_VALUE)

        for (valIn in testValues) {
            val encoded = le32(valIn)
            assertEquals(4, encoded.size)

            val bais = ByteArrayInputStream(encoded)
            val decoded = readLe32(bais)
            assertEquals("Failed for value: $valIn", valIn, decoded)
        }
    }

    @Test
    fun testFrameEOFHandling() {
        val truncated = byteArrayOf(0x01, 0x02, 0x03)
        val bais = ByteArrayInputStream(truncated)

        try {
            readLe32(bais)
            fail("Expected EOFException on truncated stream")
        } catch (e: EOFException) {
            // Expected
        }
    }

    @Test
    fun testFramedPacketBuild() {
        val jsonPayload = "{\"test\": true}"
        val payloadBytes = jsonPayload.toByteArray(Charsets.UTF_8)

        val baos = ByteArrayOutputStream()
        baos.write('E'.code)
        baos.write(le32(payloadBytes.size))
        baos.write(payloadBytes)

        val frame = baos.toByteArray()
        assertEquals(1 + 4 + payloadBytes.size, frame.size)
        assertEquals('E'.code.toByte(), frame[0])

        val bais = ByteArrayInputStream(frame)
        val type = bais.read()
        assertEquals('E'.code, type)

        val len = readLe32(bais)
        assertEquals(payloadBytes.size, len)

        val buf = ByteArray(len)
        readFully(bais, buf)
        assertEquals(jsonPayload, String(buf, Charsets.UTF_8))
    }
}
