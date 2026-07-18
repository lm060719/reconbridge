package com.reconbridge.tracer

import android.app.Activity
import android.os.Bundle
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView

/** 说明页：本模块没有本地配置，一切由 PC 端下发。 */
class MainActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val pad = 40
        val tv = TextView(this).apply {
            textSize = 14f
            text = buildString {
                append("ReconBridge Tracer (M5)\n\n")
                append("数据驱动的通用 Java trace 执行器，本身不含任何针对特定 App 的逻辑。\n\n")
                append("用法：\n")
                append("1) 在 LSPosed 里启用本模块，把要侦察的目标 App 勾进作用域；\n")
                append("2) PC 端（ReconBridge MCP）用 trace_java / post_hook 下发要 hook 的类/方法；\n")
                append("3) 重启目标 App，命中事件经守护进程实时回传到 PC（collect_events）。\n\n")
                append("模块本身跑在目标进程里，通过抽象 socket @reconbridge_inject 直连守护进程，\n")
                append("与 M3 native 执行器共用同一条链路，无需任何本地设置。\n\n")
                append("日志：adb logcat | grep ReconTracer")
            }
        }
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, pad * 2, pad, pad)
            addView(tv)
        }
        setContentView(ScrollView(this).apply { addView(root) })
    }
}
