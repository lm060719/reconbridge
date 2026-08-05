package com.reconbridge.tracer

import android.util.Log
import de.robv.android.xposed.callbacks.XC_LoadPackage
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.ZipFile

private const val TAG = "DexStringSearcher"

data class MethodMatch(
    val className: String,
    val methodName: String,
    val paramTypes: List<String>,
    val returnType: String,
    val matchedStrings: List<String>
)

object DexStringSearcher {

    /**
     * 在 app 关联的所有 DEX 文件中搜索包含 [usingStrings] 中所有字符串的方法。
     */
    fun findMatches(
        lpparam: XC_LoadPackage.LoadPackageParam,
        usingStrings: List<String>,
        classNameMatch: String? = null,
        methodNameMatch: String? = null,
        matchAllStrings: Boolean = true
    ): List<MethodMatch> {
        if (usingStrings.isEmpty()) return emptyList()

        val filesToScan = collectApkAndDexFiles(lpparam)
        Log.i(TAG, "[${lpparam.packageName}] 准备扫描 ${filesToScan.size} 个文件查找字符串: $usingStrings")

        val results = mutableListOf<MethodMatch>()
        val classRegex = if (!classNameMatch.isNullOrEmpty()) try { Regex(classNameMatch) } catch (_: Throwable) { null } else null
        val methodRegex = if (!methodNameMatch.isNullOrEmpty()) try { Regex(methodNameMatch) } catch (_: Throwable) { null } else null

        val startTime = System.currentTimeMillis()
        for (file in filesToScan) {
            try {
                val fname = file.name.lowercase()
                if (fname.endsWith(".apk") || fname.endsWith(".jar") || fname.endsWith(".zip")) {
                    ZipFile(file).use { zip ->
                        val entries = zip.entries()
                        while (entries.hasMoreElements()) {
                            val entry = entries.nextElement()
                            if (entry.name.endsWith(".dex")) {
                                zip.getInputStream(entry).use { input ->
                                    val bytes = input.readBytes()
                                    val matches = searchInDexBuffer(
                                        ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN),
                                        usingStrings, classRegex, methodRegex, matchAllStrings
                                    )
                                    results.addAll(matches)
                                }
                            }
                        }
                    }
                } else if (fname.endsWith(".dex")) {
                    val bytes = file.readBytes()
                    val matches = searchInDexBuffer(
                        ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN),
                        usingStrings, classRegex, methodRegex, matchAllStrings
                    )
                    results.addAll(matches)
                }
            } catch (t: Throwable) {
                Log.w(TAG, "扫描文件 ${file.absolutePath} 异常: $t")
            }
        }
        val cost = System.currentTimeMillis() - startTime
        val distinctResults = results.distinctBy { "${it.className}.${it.methodName}(${it.paramTypes.joinToString(",")})" }
        Log.i(TAG, "[${lpparam.packageName}] 搜索完成, 耗时 ${cost}ms, 匹配到 ${distinctResults.size} 个方法")
        return distinctResults
    }

    private fun collectApkAndDexFiles(lpparam: XC_LoadPackage.LoadPackageParam): List<File> {
        val files = mutableSetOf<File>()
        val appInfo = lpparam.appInfo
        if (appInfo != null) {
            val srcDir = appInfo.sourceDir
            if (!srcDir.isNullOrEmpty()) files.add(File(srcDir))
            val splits = appInfo.splitSourceDirs
            if (splits != null) {
                for (split in splits) {
                    if (!split.isNullOrEmpty()) files.add(File(split as String))
                }
            }
        }

        // 反射提取 ClassLoader 中的 dexElements 路径
        try {
            var curCl: ClassLoader? = lpparam.classLoader
            while (curCl != null) {
                try {
                    val getPathList = curCl.javaClass.getMethod("getPathList")
                    val pathList = getPathList.invoke(curCl)
                    if (pathList != null) {
                        val dexElementsF = pathList.javaClass.getDeclaredField("dexElements").apply { isAccessible = true }
                        val dexElements = dexElementsF.get(pathList) as? Array<*>
                        if (dexElements != null) {
                            for (elem in dexElements) {
                                if (elem == null) continue
                                try {
                                    val pathF = elem.javaClass.getDeclaredField("path").apply { isAccessible = true }
                                    val path = pathF.get(elem) as? File
                                    if (path != null && path.exists()) files.add(path)
                                } catch (_: Throwable) {}
                                try {
                                    val fileF = elem.javaClass.getDeclaredField("file").apply { isAccessible = true }
                                    val file = fileF.get(elem) as? File
                                    if (file != null && file.exists()) files.add(file)
                                } catch (_: Throwable) {}
                            }
                        }
                    }
                } catch (_: Throwable) {}
                curCl = curCl.parent
            }
        } catch (t: Throwable) {
            Log.d(TAG, "反射 ClassLoader 提取 pathList 异常: $t")
        }

        return files.filter { it.exists() }
    }

    private fun searchInDexBuffer(
        buf: ByteBuffer,
        queryStrings: List<String>,
        classRegex: Regex?,
        methodRegex: Regex?,
        matchAllStrings: Boolean
    ): List<MethodMatch> {
        if (buf.remaining() < 112) return emptyList()
        val magic = ByteArray(8)
        buf.get(magic)
        if (magic[0] != 'd'.toByte() || magic[1] != 'e'.toByte() || magic[2] != 'x'.toByte()) return emptyList()

        val stringIdsSize = buf.getInt(0x38)
        val stringIdsOff = buf.getInt(0x3C)
        val typeIdsSize = buf.getInt(0x40)
        val typeIdsOff = buf.getInt(0x44)
        val protoIdsSize = buf.getInt(0x48)
        val protoIdsOff = buf.getInt(0x4C)
        val methodIdsSize = buf.getInt(0x58)
        val methodIdsOff = buf.getInt(0x5C)
        val classDefsSize = buf.getInt(0x60)
        val classDefsOff = buf.getInt(0x64)

        // 1. 读取 string_ids，过滤匹配 queryStrings 的 string_idx 映射
        // queryIndexMap: query_string_index -> Set of string_idx in this DEX
        val queryIndexMap = HashMap<Int, MutableSet<Int>>()
        for (qIdx in queryStrings.indices) {
            queryIndexMap[qIdx] = HashSet()
        }

        for (i in 0 until stringIdsSize) {
            val off = buf.getInt(stringIdsOff + i * 4)
            val str = readMutf8String(buf, off)
            for (qIdx in queryStrings.indices) {
                val targetStr = queryStrings[qIdx]
                if (str.contains(targetStr)) {
                    queryIndexMap[qIdx]!!.add(i)
                }
            }
        }

        // 快速剪枝：如果要求匹配全部字符串，但某个 targetStr 在此 DEX 中无任何匹配 string_idx，直接返回
        if (matchAllStrings) {
            for (qIdx in queryStrings.indices) {
                if (queryIndexMap[qIdx]!!.isEmpty()) return emptyList()
            }
        }

        val allMatchedStringIndices = HashSet<Int>()
        queryIndexMap.values.forEach { allMatchedStringIndices.addAll(it) }
        if (allMatchedStringIndices.isEmpty()) return emptyList()

        // 2. 构建 type_ids -> formatted string 数组缓存
        val typeDescriptors = Array(typeIdsSize) { i ->
            val descriptorStringIdx = buf.getInt(typeIdsOff + i * 4)
            val desc = readMutf8String(buf, buf.getInt(stringIdsOff + descriptorStringIdx * 4))
            formatTypeDescriptor(desc)
        }

        // 3. 构建 proto_ids 列表：(returnType, paramTypes)
        data class ProtoInfo(val returnType: String, val paramTypes: List<String>)
        val protoInfos = Array(protoIdsSize) { i ->
            val returnTypeIdx = buf.getShort(protoIdsOff + i * 12 + 4).toInt() and 0xffff
            val returnType = typeDescriptors.getOrNull(returnTypeIdx) ?: "void"
            val paramsOff = buf.getInt(protoIdsOff + i * 12 + 8)
            val paramList = mutableListOf<String>()
            if (paramsOff != 0 && paramsOff < buf.limit()) {
                val size = buf.getInt(paramsOff)
                for (p in 0 until size) {
                    val pTypeIdx = buf.getShort(paramsOff + 4 + p * 2).toInt() and 0xffff
                    paramList.add(typeDescriptors.getOrNull(pTypeIdx) ?: "java.lang.Object")
                }
            }
            ProtoInfo(returnType, paramList)
        }

        // 4. 构建 method_ids 数组：(class_type_idx, name_string_idx, proto_idx)
        data class MethodInfo(val classTypeIdx: Int, val nameStringIdx: Int, val protoIdx: Int)
        val methodInfos = Array(methodIdsSize) { i ->
            val classTypeIdx = buf.getShort(methodIdsOff + i * 8).toInt() and 0xffff
            val protoIdx = buf.getShort(methodIdsOff + i * 8 + 2).toInt() and 0xffff
            val nameStringIdx = buf.getInt(methodIdsOff + i * 8 + 4)
            MethodInfo(classTypeIdx, nameStringIdx, protoIdx)
        }

        val matches = mutableListOf<MethodMatch>()

        // 5. 遍历 class_defs
        for (c in 0 until classDefsSize) {
            val classTypeIdx = buf.getInt(classDefsOff + c * 32)
            val className = typeDescriptors.getOrNull(classTypeIdx) ?: continue

            if (classRegex != null && !classRegex.containsMatchIn(className)) continue

            val classDataOff = buf.getInt(classDefsOff + c * 32 + 24)
            if (classDataOff == 0 || classDataOff >= buf.limit()) continue

            // 解析 class_data_item
            val posHolder = intArrayOf(classDataOff)
            val staticFieldsSize = readUleb128(buf, posHolder)
            val instanceFieldsSize = readUleb128(buf, posHolder)
            val directMethodsSize = readUleb128(buf, posHolder)
            val virtualMethodsSize = readUleb128(buf, posHolder)

            // 跳过 static_fields 和 instance_fields
            for (f in 0 until staticFieldsSize) {
                readUleb128(buf, posHolder) // field_idx_diff
                readUleb128(buf, posHolder) // access_flags
            }
            for (f in 0 until instanceFieldsSize) {
                readUleb128(buf, posHolder) // field_idx_diff
                readUleb128(buf, posHolder) // access_flags
            }

            // 处理 direct_methods
            var methodIdxAcc = 0
            for (m in 0 until directMethodsSize) {
                methodIdxAcc += readUleb128(buf, posHolder)
                val accessFlags = readUleb128(buf, posHolder)
                val codeOff = readUleb128(buf, posHolder)

                if (codeOff != 0) {
                    checkAndAddMethodMatch(
                        buf, methodIdxAcc, codeOff, className, methodInfos, protoInfos,
                        stringIdsOff, queryIndexMap, queryStrings, methodRegex, matchAllStrings, matches
                    )
                }
            }

            // 处理 virtual_methods
            methodIdxAcc = 0
            for (m in 0 until virtualMethodsSize) {
                methodIdxAcc += readUleb128(buf, posHolder)
                val accessFlags = readUleb128(buf, posHolder)
                val codeOff = readUleb128(buf, posHolder)

                if (codeOff != 0) {
                    checkAndAddMethodMatch(
                        buf, methodIdxAcc, codeOff, className, methodInfos, protoInfos,
                        stringIdsOff, queryIndexMap, queryStrings, methodRegex, matchAllStrings, matches
                    )
                }
            }
        }

        return matches
    }

    private fun checkAndAddMethodMatch(
        buf: ByteBuffer,
        methodIdx: Int,
        codeOff: Int,
        className: String,
        methodInfos: Array<*>,
        protoInfos: Array<*>,
        stringIdsOff: Int,
        queryIndexMap: Map<Int, Set<Int>>,
        queryStrings: List<String>,
        methodRegex: Regex?,
        matchAllStrings: Boolean,
        outMatches: MutableList<MethodMatch>
    ) {
        if (methodIdx >= methodInfos.size || codeOff + 16 > buf.limit()) return
        val mInfo = methodInfos[methodIdx] as? Any ?: return

        // 提取方法名
        val nameStringIdx = try {
            mInfo.javaClass.getDeclaredField("nameStringIdx").apply { isAccessible = true }.getInt(mInfo)
        } catch (_: Throwable) { return }

        val methodName = readMutf8String(buf, buf.getInt(stringIdsOff + nameStringIdx * 4))
        if (methodRegex != null && !methodRegex.containsMatchIn(methodName)) return

        // 扫描 code_item 中的指令 (insns)
        val insnsSize = buf.getInt(codeOff + 12)
        val insnsStart = codeOff + 16
        if (insnsStart + insnsSize * 2 > buf.limit()) return

        val refStringIndices = HashSet<Int>()
        var pos = 0
        while (pos < insnsSize) {
            val opcode = buf.getShort(insnsStart + pos * 2).toInt() and 0xff
            when (opcode) {
                0x1a -> { // const-string vAA, string@BBBB
                    if (pos + 1 < insnsSize) {
                        val strIdx = buf.getShort(insnsStart + (pos + 1) * 2).toInt() and 0xffff
                        refStringIndices.add(strIdx)
                    }
                    pos += 2
                }
                0x1b -> { // const-string/jumbo vAA, string@BBBBBBBB
                    if (pos + 2 < insnsSize) {
                        val low = buf.getShort(insnsStart + (pos + 1) * 2).toInt() and 0xffff
                        val high = buf.getShort(insnsStart + (pos + 2) * 2).toInt() and 0xffff
                        val strIdx = low or (high shl 16)
                        refStringIndices.add(strIdx)
                    }
                    pos += 3
                }
                else -> {
                    // 对于其他指令，安全地步进 1 个 code unit（16-bit）
                    pos += 1
                }
            }
        }

        if (refStringIndices.isEmpty()) return

        // 校验匹配条件
        val matchedQueries = mutableListOf<String>()
        for ((qIdx, targetIndices) in queryIndexMap) {
            if (targetIndices.any { refStringIndices.contains(it) }) {
                matchedQueries.add(queryStrings[qIdx])
            }
        }

        val matched = if (matchAllStrings) {
            matchedQueries.size == queryStrings.size
        } else {
            matchedQueries.isNotEmpty()
        }

        if (matched) {
            val protoIdx = mInfo.javaClass.getDeclaredField("protoIdx").apply { isAccessible = true }.getInt(mInfo)
            val pInfo = protoInfos.getOrNull(protoIdx) as? Any
            val returnType = pInfo?.javaClass?.getDeclaredField("returnType")?.apply { isAccessible = true }?.get(pInfo) as? String ?: "void"
            @Suppress("UNCHECKED_CAST")
            val paramTypes = pInfo?.javaClass?.getDeclaredField("paramTypes")?.apply { isAccessible = true }?.get(pInfo) as? List<String> ?: emptyList()

            outMatches.add(
                MethodMatch(
                    className = className,
                    methodName = methodName,
                    paramTypes = paramTypes,
                    returnType = returnType,
                    matchedStrings = matchedQueries
                )
            )
        }
    }

    private fun readUleb128(buf: ByteBuffer, posHolder: IntArray): Int {
        var result = 0
        var shift = 0
        var pos = posHolder[0]
        while (pos < buf.limit()) {
            val b = buf.get(pos).toInt() and 0xff
            pos++
            result = result or ((b and 0x7f) shl shift)
            if ((b and 0x80) == 0) break
            shift += 7
        }
        posHolder[0] = pos
        return result
    }

    private fun readMutf8String(buf: ByteBuffer, off: Int): String {
        if (off >= buf.limit()) return ""
        val posHolder = intArrayOf(off)
        readUleb128(buf, posHolder) // utf16_size
        var start = posHolder[0]
        var end = start
        while (end < buf.limit() && buf.get(end) != 0.toByte()) {
            end++
        }
        val len = end - start
        if (len <= 0) return ""
        val bytes = ByteArray(len)
        val dup = buf.duplicate()
        dup.position(start)
        dup.get(bytes)
        return String(bytes, Charsets.UTF_8)
    }

    private fun formatTypeDescriptor(desc: String): String {
        return when {
            desc == "V" -> "void"
            desc == "Z" -> "boolean"
            desc == "B" -> "byte"
            desc == "S" -> "short"
            desc == "C" -> "char"
            desc == "I" -> "int"
            desc == "J" -> "long"
            desc == "F" -> "float"
            desc == "D" -> "double"
            desc.startsWith("L") && desc.endsWith(";") -> desc.substring(1, desc.length - 1).replace('/', '.')
            desc.startsWith("[") -> {
                val component = formatTypeDescriptor(desc.substring(1))
                "$component[]"
            }
            else -> desc.replace('/', '.')
        }
    }
}
