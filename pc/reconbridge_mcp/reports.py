"""Offline investigation reports and sanitized, bounded support bundles."""
from __future__ import annotations
import hashlib
import html
import json
import re
import secrets
import zipfile
from pathlib import Path
from . import investigation, external
from .settings import settings
from .client import client

SENSITIVE = re.compile(r"token|password|passwd|secret|authorization|cookie|api.?key|credential", re.I)
CONTENT_KEYS = {"text", "content-desc", "args", "ret", "value", "this", "fields", "paths", "note", "payload", "command"}


def redact(value, key: str = ""):
    if SENSITIVE.search(key) or key.lower() in CONTENT_KEYS:
        return "[redacted]"
    if isinstance(value, dict): return {str(k): redact(v, str(k)) for k,v in value.items()}
    if isinstance(value, list): return [redact(v) for v in value]
    if isinstance(value, str):
        for token in (settings.token, getattr(client,"_token","")):
            if token: value = value.replace(token, "[redacted]")
        value = re.sub(r"(?i)(Bearer\s+)[^\s\"']+", r"\1[redacted]", value)
        value = re.sub(r"(?i)((?:token|password|secret|api_key)=)[^\s&\"']+", r"\1[redacted]", value)
        return value
    return value


def collect(session_id: str) -> tuple[dict, dict[str, bytes]]:
    state = investigation.load(session_id)
    files: dict[str, bytes] = {}
    records, omissions = [], []
    total = 0
    workflow = investigation._session_path(session_id).with_suffix(".workflow")
    events = investigation._session_path(session_id).with_suffix(".events")
    for base in (workflow, events):
        if not base.is_dir(): continue
        if base.is_symlink():
            omissions.append({"path":base.name,"reason":"symlink session folder"}); continue
        root = base.resolve()
        for index,path in enumerate(base.rglob("*")):
            if index >= 500:
                omissions.append({"path":base.name,"reason":"file scan budget"}); break
            if not path.is_file(): continue
            if path.is_symlink() or not path.resolve().is_relative_to(root):
                omissions.append({"path": path.name, "reason": "symlink/outside session"}); continue
            if path.suffix not in {".json", ".jsonl"}:
                omissions.append({"path": path.name, "reason": "raw/binary excluded"}); continue
            size = path.stat().st_size
            if len(files) >= 100 or size > 2*1024*1024 or total + size > 16*1024*1024:
                omissions.append({"path": path.name, "reason": "bundle size budget"}); continue
            try:
                data = path.read_text(encoding="utf-8")
                parsed = [json.loads(line) for line in data.splitlines() if line.strip()] if path.suffix == ".jsonl" else json.loads(data)
                sanitized = redact(parsed)
                content = json.dumps(sanitized, ensure_ascii=False, indent=2).encode()
                if total + len(content) > 16*1024*1024:
                    omissions.append({"path":path.name,"reason":"serialized bundle size budget"}); continue
                name = f"{base.suffix[1:]}/{path.relative_to(base).as_posix()}"
                files[name] = content; total += len(content)
                if path.name == "record.json": records.append(sanitized)
            except (ValueError, OSError, RecursionError) as exc:
                omissions.append({"path": path.name, "reason": str(exc)[:200]})
    document = {"schema_version":1, "session":redact(state), "toolchain":redact(external.toolchain_status()),
        "artifacts": records, "omissions": omissions, "complete": None,
        "scope": "offline stored evidence; not a fresh device diagnosis", "upstream_loss":"unknown",
        "redaction": "structured secrets and captured payload fields removed; raw XML/screenshots/traces/APKs excluded; free text may still contain identifying information"}
    return document, files


def export_investigation_report(session_id: str) -> dict:
    """Export offline JSON and escaped HTML reports plus a sanitized support ZIP with hashes.

    Includes bounded session JSON/JSONL evidence; excludes screenshots, XML, Perfetto, APKs
    and credentials. Makes no network request and does not upload any file.
    """
    document, files = collect(session_id)
    folder = investigation._session_path(session_id).with_suffix(".reports") / secrets.token_hex(8)
    folder.mkdir(parents=True, exist_ok=False)
    encoded = json.dumps(document, ensure_ascii=False, indent=2)
    files["report.json"] = encoded.encode()
    title = html.escape(str(document["session"].get("package", "Investigation")))
    rows = "".join("<tr>" + "".join(f"<td>{html.escape(str(record.get(key,'')))}</td>" for key in ("artifact_id","kind","ok","created_at")) + "</tr>" for record in document["artifacts"])
    issues = "".join(f"<li>{html.escape(str(item))}</li>" for item in document["omissions"])
    page = f'<!doctype html><html lang="zh"><meta charset="utf-8"><title>{title} — ReconBridge</title><style>body{{font:16px system-ui;max-width:1000px;margin:40px auto;padding:0 20px}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#f4f5f7;padding:20px}}h1{{font-size:28px}}td,th{{padding:8px;text-align:left;border-bottom:1px solid #ddd}}</style><h1>{title}</h1><p>会话 {html.escape(session_id)} · 离线调查记录 · 完整性未确认</p><h2>采集与执行结果</h2><p>{len(document["artifacts"])} 个工作流记录；原始图像和二进制不包含在故障包内。</p><table><tr><th>证据 ID</th><th>类型</th><th>执行成功</th><th>时间（毫秒）</th></tr>{rows}</table><h2>未纳入的文件</h2><ul>{issues}</ul><h2>结构化证据与限制</h2><pre>{html.escape(encoded)}</pre></html>'
    files["report.html"] = page.encode()
    manifest = {"schema_version":1, "files":{name:{"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest()} for name,data in files.items()}}
    files["manifest.json"] = json.dumps(manifest,indent=2).encode()
    for name in ("report.json","report.html","manifest.json"): (folder/name).write_bytes(files[name])
    archive_path = folder/"support-bundle.zip"
    with zipfile.ZipFile(archive_path,"x",zipfile.ZIP_DEFLATED) as archive:
        for name,data in files.items(): archive.writestr(name,data)
    with zipfile.ZipFile(archive_path) as archive:
        for name,expected in manifest["files"].items():
            data = archive.read(name)
            if len(data) != expected["bytes"] or hashlib.sha256(data).hexdigest() != expected["sha256"]:
                raise ValueError("report bundle verification failed")
    return {"ok":True,"session_id":session_id,"report_json":str(folder/"report.json"),
            "report_html":str(folder/"report.html"),"support_bundle":str(archive_path),
            "sha256":hashlib.sha256(archive_path.read_bytes()).hexdigest(),"omissions":document["omissions"],
            "uploaded":False,"complete":None}


def register(mcp) -> None:
    mcp.tool()(export_investigation_report)
