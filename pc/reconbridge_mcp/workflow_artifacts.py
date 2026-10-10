"""Session-owned artifact directories shared by UI, tracing and reports."""
from __future__ import annotations
import hashlib
import json
import secrets
import time
from pathlib import Path
from . import investigation


def create(session_id: str, kind: str) -> tuple[dict, Path]:
    state = investigation.load(session_id)
    folder = investigation._session_path(session_id).with_suffix(".workflow") / secrets.token_hex(8)
    folder.mkdir(parents=True, exist_ok=False)
    record = {"artifact_id": folder.name, "session_id": session_id, "package": state["package"],
              "kind": kind, "created_at": int(time.time() * 1000), "files": {}}
    return record, folder


def finish(record: dict, folder: Path) -> dict:
    for path in sorted(folder.iterdir()):
        if path.is_file() and path.name != "record.json":
            record["files"][path.name] = {"bytes": path.stat().st_size,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    (folder / "record.json").write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
    return {**record, "artifact_dir": str(folder)}
