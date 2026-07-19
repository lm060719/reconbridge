package com.reconbridge.tracer

import android.net.LocalSocket
import android.net.LocalSocketAddress
import android.util.Log
import java.io.EOFException
import java.io.InputStream
import java.io.OutputStream

/**
 * 详细日志开关。默认 false（安静：只在装 hook / 出错时打日志）。
 * PC 下发配置里 `"debug": true` 时置真，逐命中日志（HIT / sendEvent ok）才输出。
 * 进程级即可（模块在每个目标进程各跑一份，互不影响）。
 */
@Volatile
internal var traceVerbose = false

/**
 * 复刻 ReconBridge M3 的注入 IPC 协议（见 src/dynamic.cpp inject_client）。
 *
 * 本模块跑在目标 App 进程（app SELinux 域），沿用 M3 注入层同一条链路直连守护进程
 * （u:r:ksu:s0，sepolicy.rule 已放行 appdomain->ksu connectto）的抽象 socket
 * @reconbridge_inject，取本包 hook 配置，并把命中事件回传（守护进程再广播给 SSE/WS）。
 *
 * 线路（握手后转为双向分帧）：
 *   client -> [plen:4 LE][pkg]
 *   server -> [has:1]                （0 = 本包无配置）
 *   server -> [clen:4 LE][cfg]        （has=1 时）
 *   client -> [type:1='E'][len:4 LE][json]  （每次命中，反复）
 *   client -> [type:1='H'][len:4 LE=0]      （声明可热加，P0-2；native 层不发）
 *   server -> [type:1='R'][len:4 LE][cfg]   （免重启热加：下发新配置，tracer 增量装新 target）
 *
 * 所有整数为小端（守护进程按原生内存布局收发，arm64 = LE）。
 */
class InjectSocket private constructor(
    private val socket: LocalSocket,
    private val output: OutputStream,
    private val input: InputStream,
) {
    private val writeLock = Any()
    @Volatile private var alive = true

    /**
     * 免重启热加（P0-2）：向守护进程声明"可热加"（发 'H' 帧），并起读线程监听 daemon 下发的
     * 'R'(reload) 控制帧——收到时把新配置文本交给 onReload（HookEntry 增量装新 target）。
     * 只有 tracer 调用本方法，故 native 层不会被 daemon 下发 'R'。
     */
    fun enableHotReload(onReload: (String) -> Unit) {
        synchronized(writeLock) {
            if (!alive) return
            try {
                output.write('H'.code)
                output.write(le32(0))
                output.flush()
            } catch (t: Throwable) {
                alive = false
                Log.w("ReconTracer", "声明可热加失败: $t")
                return
            }
        }
        Thread({
            try {
                while (alive) {
                    val type = input.read()
                    if (type < 0) break
                    val len = readLe32(input)
                    if (len < 0 || len > MAX_CFG) break
                    val buf = ByteArray(len)
                    if (len > 0) readFully(input, buf)
                    if (type == 'R'.code) {
                        val cfg = String(buf, Charsets.UTF_8)
                        try {
                            onReload(cfg)
                        } catch (t: Throwable) {
                            Log.w("ReconTracer", "热加处理异常: $t")
                        }
                    }
                    // 其它类型忽略（前向兼容）
                }
            } catch (_: Throwable) {
                // 通道断开，静默
            }
        }, "ReconTracer-reload").apply { isDaemon = true; start() }
    }

    /** 回传一条事件 JSON，分帧 ['E'][len:4 LE][payload]。线程安全；断开后静默丢弃。 */
    fun sendEvent(json: String) {
        if (!alive) return
        val payload = json.toByteArray(Charsets.UTF_8)
        synchronized(writeLock) {
            if (!alive) return
            try {
                output.write('E'.code)
                output.write(le32(payload.size))
                output.write(payload)
                output.flush()
                if (traceVerbose) Log.i("ReconTracer", "sendEvent ok ${payload.size}B")
            } catch (t: Throwable) {
                alive = false
                Log.w("ReconTracer", "sendEvent 失败，通道断开: $t")
                try { socket.close() } catch (_: Throwable) {}
            }
        }
    }

    companion object {
        private const val NAME = "reconbridge_inject"
        private const val MAX_CFG = 16 shl 20

        /**
         * 连守护进程并取本包配置。
         * @return (socket, 配置JSON文本)；连不上或本包无配置返回 null。
         */
        fun connectAndFetch(pkg: String): Pair<InjectSocket, String>? {
            val sock = LocalSocket()
            try {
                sock.connect(LocalSocketAddress(NAME, LocalSocketAddress.Namespace.ABSTRACT))
            } catch (t: Throwable) {
                return null
            }
            try {
                val input = sock.inputStream
                val output = sock.outputStream

                val pkgBytes = pkg.toByteArray(Charsets.UTF_8)
                output.write(le32(pkgBytes.size))
                output.write(pkgBytes)
                output.flush()

                val has = input.read()
                if (has != 1) { sock.close(); return null }

                val clen = readLe32(input)
                if (clen <= 0 || clen > MAX_CFG) { sock.close(); return null }
                val cfg = ByteArray(clen)
                readFully(input, cfg)

                return InjectSocket(sock, output, input) to String(cfg, Charsets.UTF_8)
            } catch (t: Throwable) {
                try { sock.close() } catch (_: Throwable) {}
                return null
            }
        }

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
    }
}
