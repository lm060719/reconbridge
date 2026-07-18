"""PC 本地反编译工具链集成：jadx / DexKit(用 androguard 实现) / Ghidra headless / Hermes。

工具路径优先用环境变量，其次在 pc/tools 下按约定探测。工具缺失时返回清晰的安装指引，
不抛裸异常，方便 Claude Code 侧继续决策。
"""
from __future__ import annotations

import glob
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Optional

from .settings import settings

COMSPEC = os.environ.get("COMSPEC", "cmd.exe")

# androguard 用 loguru 输出海量 DEBUG 日志；全局静默，避免噪声（stdio MCP 尤其要保持干净）
try:
    from loguru import logger as _loguru
    _loguru.remove()
except Exception:
    pass


# ---------------------------------------------------------------------------
# 工具探测
# ---------------------------------------------------------------------------
def _find_jadx() -> Optional[Path]:
    if settings.jadx:
        p = Path(settings.jadx)
        if p.exists():
            return p
    for cand in [
        settings.tools_dir / "jadx" / "bin" / ("jadx.bat" if os.name == "nt" else "jadx"),
    ]:
        if cand.exists():
            return cand
    which = shutil.which("jadx")
    return Path(which) if which else None


def _find_ghidra_headless() -> Optional[Path]:
    if settings.ghidra:
        root = Path(settings.ghidra)
        hs = root / "support" / ("analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless")
        if hs.exists():
            return hs
    name = "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"
    hits = (glob.glob(str(settings.native_tools_dir / "ghidra*" / "support" / name))
            + glob.glob(str(settings.tools_dir / "ghidra*" / "support" / name)))
    return Path(hits[0]) if hits else None


def _find_jdk21() -> Optional[Path]:
    """给 Ghidra 用的 JDK 21（Ghidra 12 需要 21+，系统可能是 17）。"""
    hits = (glob.glob(str(settings.native_tools_dir / "jdk-21*"))
            + glob.glob(str(settings.tools_dir / "jdk-21*")))
    for h in hits:
        jhome = Path(h)
        # 解压后可能多套一层
        if (jhome / "bin").exists():
            return jhome
        inner = glob.glob(str(jhome / "jdk-21*"))
        if inner and (Path(inner[0]) / "bin").exists():
            return Path(inner[0])
    return None


def toolchain_status() -> dict:
    jadx = _find_jadx()
    ghidra = _find_ghidra_headless()
    jdk = _find_jdk21()
    try:
        import androguard  # noqa: F401
        import importlib.metadata as m
        andro = m.version("androguard")
    except Exception:
        andro = None
    return {
        "jadx": str(jadx) if jadx else None,
        "androguard": andro,  # dexkit_search 的后端
        "ghidra_headless": str(ghidra) if ghidra else None,
        "ghidra_jdk21": str(jdk) if jdk else None,
        "system_java": shutil.which("java"),
        "hints": {
            "jadx": None if jadx else "缺 jadx：下载 https://github.com/skylot/jadx 解压到 pc/tools/jadx",
            "ghidra": None if ghidra else "缺 Ghidra：解压到 pc/tools/ghidra_*",
            "dexkit": None if andro else "缺 androguard：pip install androguard",
        },
    }


# ---------------------------------------------------------------------------
# jadx
# ---------------------------------------------------------------------------
def decompile_apk(apk_path: str, output_dir: str = "", no_res: bool = True) -> dict:
    jadx = _find_jadx()
    if not jadx:
        return {"ok": False, "error": "jadx 未就绪", "hint": toolchain_status()["hints"]["jadx"]}
    apk = Path(apk_path)
    if not apk.exists():
        return {"ok": False, "error": f"apk 不存在: {apk_path}"}
    out = Path(output_dir) if output_dir else apk.parent / (apk.stem + "-jadx")
    out.mkdir(parents=True, exist_ok=True)

    cmd = [COMSPEC, "/c", str(jadx), "-d", str(out)]
    if no_res:
        cmd.append("--no-res")  # 跳过资源，只出 Java 源码，快
    cmd.append(str(apk))
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=settings.timeout,
                       encoding="utf-8", errors="replace")
    java_files = list(out.rglob("*.java"))
    ok = out.exists() and len(java_files) > 0
    return {
        "ok": ok,
        "output_dir": str(out),
        "java_file_count": len(java_files),
        "sources_root": str(out / "sources"),
        "jadx_exit": p.returncode,
        "log_tail": (p.stdout + p.stderr)[-1500:],
    }


# ---------------------------------------------------------------------------
# dexkit_search —— 用 androguard 做类/方法/字段/字符串定位
# ---------------------------------------------------------------------------
def dexkit_search(apk_path: str, query: dict) -> dict:
    apk = Path(apk_path)
    if not apk.exists():
        return {"ok": False, "error": f"apk 不存在: {apk_path}"}
    try:
        from androguard.misc import AnalyzeAPK
    except Exception:
        return {"ok": False, "error": "androguard 未安装", "hint": "pip install androguard"}

    import re as _re

    def _pat(p: str) -> str:
        """普通名字（无正则元字符）按子串匹配；否则当正则透传。androguard 的匹配是锚定的，
        故对普通 token 包成 .*token.* 以符合直觉。"""
        if not p or p == ".*":
            return ".*"
        if _re.search(r"[\\^$.|?*+()\[\]{}]", p):
            return p
        return ".*" + _re.escape(p) + ".*"

    find = query.get("find", "method")
    limit = int(query.get("max_results", 100))
    results: list[dict] = []
    try:
        a, dlist, dx = AnalyzeAPK(str(apk))
    except Exception as e:
        return {"ok": False, "error": f"androguard 解析失败: {e}"}

    def meth_row(ma) -> dict:
        # ma 可能是 MethodClassAnalysis / MethodAnalysis / EncodedMethod / ExternalMethod
        m = ma.get_method() if hasattr(ma, "get_method") else ma
        return {
            "class": m.get_class_name(),
            "method": m.get_name(),
            "descriptor": m.get_descriptor() if hasattr(m, "get_descriptor") else "",
            "access": m.get_access_flags_string() if hasattr(m, "get_access_flags_string") else "",
        }

    try:
        if find == "string":
            pat = query.get("string", ".*")
            for s in dx.find_strings(pat):
                results.append({"string": s.get_value()})
                if len(results) >= limit:
                    break
        elif find == "class":
            pat = _pat(query.get("class_name", ".*"))
            for c in dx.find_classes(pat):
                results.append({"class": c.name})
                if len(results) >= limit:
                    break
        elif find == "field":
            fpat = _pat(query.get("field_name", ".*"))
            cpat = _pat(query.get("class_name", ".*"))
            for fa in dx.find_fields(classname=cpat, fieldname=fpat):
                f = fa.get_field()
                results.append({"class": f.get_class_name(), "field": f.get_name(),
                                "type": f.get_descriptor()})
                if len(results) >= limit:
                    break
        else:  # method
            using = query.get("using_strings")
            if using:
                seen = set()
                for kw in using:
                    for s in dx.find_strings(kw):
                        for xref in s.get_xref_from():
                            # androguard 各版本 xref 元组可能是 (class, method) 或 (class, method, offset)
                            row = meth_row(xref[1])
                            key = (row["class"], row["method"], row["descriptor"])
                            if key in seen:
                                continue
                            seen.add(key)
                            row["matched_string"] = kw
                            results.append(row)
                            if len(results) >= limit:
                                break
            else:
                cpat = _pat(query.get("class_name", ".*"))
                mpat = _pat(query.get("method_name", ".*"))
                for ma in dx.find_methods(classname=cpat, methodname=mpat):
                    results.append(meth_row(ma))
                    if len(results) >= limit:
                        break
    except Exception as e:
        return {"ok": False, "error": f"查询失败: {e}", "query": query}

    return {"ok": True, "backend": "androguard", "find": find,
            "count": len(results), "results": results}


# ---------------------------------------------------------------------------
# Ghidra headless
# ---------------------------------------------------------------------------
_GHIDRA_SCRIPT = "ReconExport.java"  # Ghidra 12 移除 Jython，用 Java GhidraScript


def _ensure_ghidra_script() -> Path:
    """把分析脚本写到 ASCII 路径下的 ghidra_scripts，供 headless -postScript 使用。
    （Ghidra 对非 ASCII 路径不友好，故与 Ghidra 安装同放 native_tools_dir。）"""
    d = settings.native_tools_dir / "ghidra_scripts"
    d.mkdir(parents=True, exist_ok=True)
    sp = d / _GHIDRA_SCRIPT
    sp.write_text(_GHIDRA_SCRIPT_SRC, encoding="utf-8")
    return d


def ghidra_analyze(so_path: str, options: dict) -> dict:
    hs = _find_ghidra_headless()
    if not hs:
        return {"ok": False, "error": "Ghidra 未就绪", "hint": toolchain_status()["hints"]["ghidra"]}
    so = Path(so_path)
    if not so.exists():
        return {"ok": False, "error": f"so 不存在: {so_path}"}

    import json as _json
    import tempfile

    out_json = Path(tempfile.gettempdir()) / f"ghidra_{so.stem}.json"
    if out_json.exists():
        out_json.unlink()

    script_dir = _ensure_ghidra_script()
    # Ghidra 工程目录也要 ASCII，放 native_tools_dir 下
    proj_dir = settings.native_tools_dir / "_ghidra_proj"
    proj_dir.mkdir(parents=True, exist_ok=True)
    # 输入 .so 复制到 ASCII 路径再导入，规避 Ghidra 对非 ASCII 输入路径的问题
    in_dir = settings.native_tools_dir / "_ghidra_in"
    in_dir.mkdir(parents=True, exist_ok=True)
    import_target = in_dir / so.name
    shutil.copy2(so, import_target)

    env = os.environ.copy()
    jdk = _find_jdk21()
    if jdk:
        # Ghidra 12 需 JDK21；系统可能是 17。JAVA_HOME_OVERRIDE 是 Ghidra 启动脚本认的变量
        env["JAVA_HOME"] = str(jdk)
        env["JAVA_HOME_OVERRIDE"] = str(jdk)

    # 通过环境变量把选项与输出路径传给 Java 脚本（避免脚本内再解析 JSON）
    env["RECON_OUT"] = str(out_json)
    env["RECON_STR_MINLEN"] = str(int(options.get("strings_min_len", 5)))
    env["RECON_MAX_FUNCS"] = str(int(options.get("max_functions", 400)))
    decompile = options.get("decompile", []) or []
    env["RECON_DECOMPILE"] = ",".join(str(x) for x in decompile)

    cmd = [
        COMSPEC, "/c", str(hs), str(proj_dir), f"recon_{so.stem}",
        "-import", str(import_target), "-overwrite",
        "-scriptPath", str(script_dir),
        "-postScript", _GHIDRA_SCRIPT,
    ]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=settings.timeout,
                       env=env, encoding="utf-8", errors="replace")
    if out_json.exists():
        data = _json.loads(out_json.read_text(encoding="utf-8"))
        return {"ok": True, "so": str(so), "analysis": data, "ghidra_exit": p.returncode}
    return {"ok": False, "error": "Ghidra 未产出结果",
            "ghidra_exit": p.returncode, "log_tail": (p.stdout + p.stderr)[-2000:]}


# Ghidra headless 里跑的 Java GhidraScript：导出/导入表、字符串、函数、可疑函数、可选反编译。
# Ghidra 12 移除了 Jython，Java GhidraScript 由 headless 原生编译运行，无需 PyGhidra。
# 选项经环境变量传入；结果手动拼 JSON（含转义）写到 RECON_OUT。
_GHIDRA_SCRIPT_SRC = r'''// ReconBridge Ghidra 导出脚本（Java GhidraScript）。由 analyzeHeadless -postScript 调用。
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.app.decompiler.*;
import ghidra.util.task.ConsoleTaskMonitor;
import java.io.*;
import java.util.*;

public class ReconExport extends GhidraScript {

    static String esc(String s) {
        if (s == null) return "";
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':  b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default:
                    if (c < 0x20) b.append(String.format("\\u%04x", (int) c));
                    else b.append(c);
            }
        }
        return b.toString();
    }

    static int envInt(String k, int dflt) {
        try { String v = System.getenv(k); return v == null ? dflt : Integer.parseInt(v.trim()); }
        catch (Exception e) { return dflt; }
    }

    @Override
    public void run() throws Exception {
        String outPath = System.getenv("RECON_OUT");
        int minLen = envInt("RECON_STR_MINLEN", 5);
        int maxFuncs = envInt("RECON_MAX_FUNCS", 400);
        String decEnv = System.getenv("RECON_DECOMPILE");
        List<String> wantDec = new ArrayList<>();
        if (decEnv != null && !decEnv.trim().isEmpty())
            for (String t : decEnv.split(",")) if (!t.trim().isEmpty()) wantDec.add(t.trim());

        Program prog = getCurrentProgram();
        FunctionManager fm = prog.getFunctionManager();
        SymbolTable st = prog.getSymbolTable();

        // 导出/导入符号
        StringBuilder exportsJson = new StringBuilder("[");
        List<String[]> exportList = new ArrayList<>();  // name, addr
        StringBuilder importsJson = new StringBuilder("[");
        int expN = 0, impN = 0;
        for (Symbol sym : st.getAllSymbols(true)) {
            try {
                if (sym.isExternal()) {
                    if (impN < 1000) {
                        if (impN > 0) importsJson.append(",");
                        importsJson.append("\"").append(esc(sym.getName())).append("\"");
                    }
                    impN++;
                } else if (sym.isGlobal() && sym.getSymbolType() == SymbolType.FUNCTION && sym.isPrimary()) {
                    String nm = sym.getName();
                    String ad = sym.getAddress().toString();
                    exportList.add(new String[]{nm, ad});
                    if (expN < 1000) {
                        if (expN > 0) exportsJson.append(",");
                        exportsJson.append("{\"name\":\"").append(esc(nm))
                                   .append("\",\"addr\":\"").append(esc(ad)).append("\"}");
                    }
                    expN++;
                }
            } catch (Exception e) { }
        }
        exportsJson.append("]");
        importsJson.append("]");

        // 函数列表
        StringBuilder funcsJson = new StringBuilder("[");
        int fN = 0;
        for (Function fn : fm.getFunctions(true)) {
            if (fN >= maxFuncs) break;
            if (fN > 0) funcsJson.append(",");
            funcsJson.append("{\"name\":\"").append(esc(fn.getName()))
                     .append("\",\"addr\":\"").append(esc(fn.getEntryPoint().toString()))
                     .append("\",\"size\":").append(fn.getBody().getNumAddresses()).append("}");
            fN++;
        }
        funcsJson.append("]");

        // 字符串
        StringBuilder strJson = new StringBuilder("[");
        int sN = 0;
        DataIterator dit = prog.getListing().getDefinedData(true);
        while (dit.hasNext()) {
            Data d = dit.next();
            try {
                Object v = d.getValue();
                if (v instanceof String) {
                    String s = (String) v;
                    if (s.length() >= minLen) {
                        if (sN < 2000) {
                            if (sN > 0) strJson.append(",");
                            strJson.append("{\"addr\":\"").append(esc(d.getAddress().toString()))
                                   .append("\",\"value\":\"").append(esc(s)).append("\"}");
                        }
                        sN++;
                    }
                }
            } catch (Exception e) { }
        }
        strJson.append("]");

        // 可疑函数（导出名命中加解密/签名/校验关键词）
        String[] KW = {"encrypt","decrypt","sign","md5","sha","aes","des","rc4","hmac","crypt",
                       "verify","check","token","secret","key","license","auth","hash","base64","cert"};
        StringBuilder suspJson = new StringBuilder("[");
        int suN = 0;
        for (String[] ex : exportList) {
            String ln = ex[0].toLowerCase();
            boolean hit = false;
            for (String k : KW) if (ln.contains(k)) { hit = true; break; }
            if (hit) {
                if (suN > 0) suspJson.append(",");
                suspJson.append("{\"name\":\"").append(esc(ex[0]))
                        .append("\",\"addr\":\"").append(esc(ex[1])).append("\"}");
                suN++;
            }
        }
        suspJson.append("]");

        // 可选反编译
        StringBuilder decJson = new StringBuilder("{");
        int dN = 0;
        if (!wantDec.isEmpty()) {
            DecompInterface di = new DecompInterface();
            di.openProgram(prog);
            ConsoleTaskMonitor mon = new ConsoleTaskMonitor();
            for (String target : wantDec) {
                Function fn = null;
                try {
                    if (target.startsWith("0x") || target.matches("\\d+")) {
                        long off = target.startsWith("0x") ? Long.parseLong(target.substring(2), 16)
                                                           : Long.parseLong(target);
                        Address a = prog.getAddressFactory().getDefaultAddressSpace().getAddress(off);
                        fn = fm.getFunctionContaining(a);
                    } else {
                        for (Function c : fm.getFunctions(true))
                            if (c.getName().equals(target)) { fn = c; break; }
                    }
                } catch (Exception e) { fn = null; }
                if (fn != null) {
                    try {
                        DecompileResults res = di.decompileFunction(fn, 60, mon);
                        if (res.decompileCompleted()) {
                            if (dN > 0) decJson.append(",");
                            decJson.append("\"").append(esc(target)).append("\":\"")
                                   .append(esc(res.getDecompiledFunction().getC())).append("\"");
                            dN++;
                        }
                    } catch (Exception e) { }
                }
            }
        }
        decJson.append("}");

        StringBuilder out = new StringBuilder();
        out.append("{\"program\":\"").append(esc(prog.getName())).append("\"")
           .append(",\"exports_count\":").append(expN).append(",\"exports\":").append(exportsJson)
           .append(",\"imports_count\":").append(impN).append(",\"imports\":").append(importsJson)
           .append(",\"functions_count\":").append(fN).append(",\"functions\":").append(funcsJson)
           .append(",\"strings_count\":").append(sN).append(",\"strings\":").append(strJson)
           .append(",\"suspicious\":").append(suspJson)
           .append(",\"decompiled\":").append(decJson)
           .append("}");

        try (Writer w = new OutputStreamWriter(new FileOutputStream(outPath), "UTF-8")) {
            w.write(out.toString());
        }
        println("[ReconExport] wrote " + outPath);
    }
}
'''


# ---------------------------------------------------------------------------
# Hermes (.hbc) 反编译
# ---------------------------------------------------------------------------
def hermes_decompile(bundle_path: str, output_dir: str = "") -> dict:
    b = Path(bundle_path)
    if not b.exists():
        return {"ok": False, "error": f"bundle 不存在: {bundle_path}"}
    out = Path(output_dir) if output_dir else b.parent / (b.stem + "-hermes")
    out.mkdir(parents=True, exist_ok=True)

    # 优先 hbctool（若已安装）
    hbc = shutil.which("hbctool")
    if hbc:
        p = subprocess.run([hbc, "disasm", str(b), str(out)],
                           capture_output=True, text=True, timeout=settings.timeout,
                           encoding="utf-8", errors="replace")
        produced = list(out.rglob("*"))
        return {"ok": bool(produced), "tool": "hbctool", "output_dir": str(out),
                "files": len(produced), "exit": p.returncode,
                "log_tail": (p.stdout + p.stderr)[-1500:]}

    # 退回：识别 Hermes 版本号，给出后续指引（hbctool 强依赖版本，需匹配）
    ver = None
    try:
        with open(b, "rb") as fp:
            head = fp.read(20)
        if head[:8] == b"\xc6\x1f\xbc\x03\xc1\x03\x19\x1f":  # Hermes magic
            ver = int.from_bytes(head[8:12], "little")
    except Exception:
        pass
    return {"ok": False,
            "error": "未检测到可用的 Hermes 反编译器",
            "hermes_bytecode_version": ver,
            "hint": "pip install hbctool（注意其对 Hermes 版本敏感），或用 hermes-dec / hasmer；"
                    "也可先确认该 bundle 是否 Hermes（magic c61fbc03…）"}
