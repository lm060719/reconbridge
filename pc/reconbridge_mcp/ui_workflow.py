"""UI Automator snapshots and explicit, selector-based replay with receipts."""
from __future__ import annotations
import hashlib
import json
import re
import secrets
import time
import xml.etree.ElementTree as ET
from . import device_tools as device, workflow_artifacts, investigation
from .observability import validate_package, safe_error, event_integrity
from .client import client

SELECTORS = {"resource-id", "text", "content-desc", "class"}


def parse_hierarchy(data: bytes, package: str) -> dict:
    if len(data) > 4 * 1024 * 1024 or b"<!DOCTYPE" in data.upper() or b"<!ENTITY" in data.upper():
        raise ValueError("oversized/unsafe UI hierarchy")
    root = ET.fromstring(data)
    if root.tag != "hierarchy":
        raise ValueError("UI hierarchy root missing")
    nodes = []
    for elem in root.iter("node"):
        if len(nodes) >= 10000:
            raise ValueError("UI hierarchy exceeds 10000 nodes")
        attrs = elem.attrib
        node = {key: attrs.get(key, "") for key in (*sorted(SELECTORS), "package", "bounds")}
        for key in ("clickable", "enabled", "password", "focused", "scrollable"):
            node[key] = attrs.get(key) == "true"
        match = re.fullmatch(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", node["bounds"])
        node["rect"] = list(map(int, match.groups())) if match else None
        if node["rect"] and (max(node["rect"]) > 100000 or node["rect"][0] >= node["rect"][2] or node["rect"][1] >= node["rect"][3]):
            node["rect"] = None
        if node["password"]:
            node["text"] = "[redacted]"
        nodes.append(node)
    target = [node for node in nodes if node["package"] == package]
    if not target:
        raise ValueError("target package is absent from the visible hierarchy")
    canonical = json.dumps(nodes, sort_keys=True, ensure_ascii=False).encode()
    return {"rotation": root.attrib.get("rotation"), "nodes": nodes, "node_count": len(nodes),
            "target_node_count": len(target), "hierarchy_sha256": hashlib.sha256(canonical).hexdigest()}


def snapshot(package: str, screenshot: bool = False) -> tuple[dict, bytes, bytes | None]:
    validate_package(package)
    remote = f"/data/local/tmp/rb-ui-{secrets.token_hex(8)}.xml"
    started = int(time.time() * 1000)
    try:
        device.shell("uiautomator", "dump", "--compressed", remote, timeout=25)
        xml = device.adb_bytes("exec-out", "cat", remote, max_bytes=4 * 1024 * 1024)
        tree = parse_hierarchy(xml, package)
        png = device.adb_bytes("exec-out", "screencap", "-p", max_bytes=24 * 1024 * 1024) if screenshot else None
        if png is not None and not png.startswith(b"\x89PNG\r\n\x1a\n"):
            raise ValueError("invalid screenshot output")
        tree.update(capture_started_at=started, capture_finished_at=int(time.time() * 1000),
                    atomic_snapshot=False, serial=device.client._serial)
        return tree, xml, png
    finally:
        try: device.shell("rm", "-f", remote, timeout=10)
        except Exception: pass


def capture_ui(session_id: str, screenshot: bool = True) -> dict:
    """Capture target UI hierarchy and optional screenshot via adb into the investigation session."""
    record, folder = workflow_artifacts.create(session_id, "ui_snapshot")
    try:
        tree, xml, png = snapshot(record["package"], screenshot)
        (folder / "hierarchy.xml").write_bytes(xml)
        (folder / "hierarchy.json").write_text(json.dumps(tree, ensure_ascii=False, indent=2), encoding="utf-8")
        if png is not None: (folder / "screenshot.png").write_bytes(png)
        record.update(ok=True, hierarchy_sha256=tree["hierarchy_sha256"], node_count=tree["node_count"],
                      serial=tree["serial"], atomic_snapshot=False)
    except Exception as exc:
        record.update(ok=False, error=safe_error(exc))
    return workflow_artifacts.finish(record, folder)


def select_node(tree: dict, selector: dict, package: str) -> dict:
    if not isinstance(selector, dict) or not selector or set(selector) - SELECTORS:
        raise ValueError("selector requires resource-id/text/content-desc/class exact matches")
    if any(not isinstance(value, str) or not value or len(value) > 512 for value in selector.values()):
        raise ValueError("selector values must be nonempty strings of at most 512 characters")
    matched = [node for node in tree["nodes"] if node["package"] == package and node["rect"]
               and all(node.get(key) == value for key, value in selector.items())]
    if len(matched) != 1:
        raise ValueError(f"selector must match exactly one target node; matched {len(matched)}")
    return matched[0]


def validate_steps(steps: list[dict]) -> None:
    if not isinstance(steps, list) or not 1 <= len(steps) <= 50:
        raise ValueError("steps must contain 1..50 actions")
    for step in steps:
        if not isinstance(step, dict) or step.get("action") not in {"tap", "assert", "text", "key"}:
            raise ValueError("supported actions: tap/assert/text/key")
        if set(step) - {"action", "selector", "text", "key", "expected_hierarchy_sha256"}:
            raise ValueError("unknown UI step field")
        if step["action"] in {"tap", "assert", "text"}:
            selector = step.get("selector")
            if not isinstance(selector, dict) or not selector or set(selector) - SELECTORS:
                raise ValueError("an exact target selector is required")
            if any(not isinstance(v, str) or not v or len(v) > 512 for v in selector.values()):
                raise ValueError("invalid selector value")
        if step["action"] == "key" and step.get("key") not in {"BACK", "ENTER"}:
            raise ValueError("key must be BACK or ENTER")
        if step["action"] == "text":
            text = step.get("text")
            if not isinstance(text, str) or not 1 <= len(text) <= 200 or any(ord(c) < 32 or ord(c) > 126 or c == '%' for c in text):
                raise ValueError("text supports 1..200 printable ASCII characters excluding %")
        expected = step.get("expected_hierarchy_sha256")
        if expected is not None and (not isinstance(expected, str) or not re.fullmatch("[a-f0-9]{64}", expected)):
            raise ValueError("invalid expected hierarchy fingerprint")


def replay_ui_steps(session_id: str, steps: list[dict], execute: bool = False, capture_events: bool = True) -> dict:
    """Validate or execute up to 50 UI actions; save fresh before/after snapshots and stop on mismatch.

    execute=False only validates the plan locally. execute=True performs actions immediately.
    Exact selectors must match one node; text additionally requires an already-focused field.
    Input acknowledgement is not business success: include explicit assert steps for expected UI.
    """
    validate_steps(steps)
    state = investigation.load(session_id)
    if not execute:
        return {"ok": True, "executed": False, "package": state["package"], "steps": steps,
                "device_preconditions_checked": False}
    record, folder = workflow_artifacts.create(session_id, "ui_replay")
    record.update(ok=False, executed=True, steps=steps, receipts=[])
    for index, step in enumerate(steps):
        receipt = {"index": index, "action": step["action"], "input_sent": False, "input_attempted": False}
        record["receipts"].append(receipt)
        cursor = None
        if capture_events:
            try: cursor = client.get_recent(limit=0)
            except Exception as exc: receipt["event_capture_error"] = safe_error(exc)
        try:
            before, _, _ = snapshot(state["package"])
            (folder / f"{index:02d}-before.json").write_text(json.dumps(before, ensure_ascii=False), encoding="utf-8")
            receipt["before_sha256"] = before["hierarchy_sha256"]
            if step.get("expected_hierarchy_sha256", before["hierarchy_sha256"]) != before["hierarchy_sha256"]:
                raise ValueError("UI precondition changed; action not sent")
            action = step["action"]
            if action in {"tap", "text", "assert"}:
                node = select_node(before, step["selector"], state["package"])
                if action != "assert" and not node["enabled"]:
                    raise ValueError("selected node is disabled")
                if action == "tap":
                    if not node["clickable"]: raise ValueError("selected node is not clickable")
                    x1, y1, x2, y2 = node["rect"]
                    receipt["input_attempted"] = True
                    device.shell("input", "tap", str((x1+x2)//2), str((y1+y2)//2))
                elif action == "text":
                    if not node["focused"]: raise ValueError("text requires an already-focused target field")
                    receipt["input_attempted"] = True
                    device.shell("input", "text", step["text"].replace(" ", "%s"))
            else:
                receipt["input_attempted"] = True
                device.shell("input", "keyevent", {"BACK": "4", "ENTER": "66"}[step["key"]])
            receipt["input_sent"] = action != "assert"
            after, _, _ = snapshot(state["package"])
            (folder / f"{index:02d}-after.json").write_text(json.dumps(after, ensure_ascii=False), encoding="utf-8")
            receipt.update(ok=True, after_sha256=after["hierarchy_sha256"], business_result_verified=False)
        except Exception as exc:
            receipt.update(ok=False, error=safe_error(exc), effect_unknown=receipt["input_attempted"])
        finally:
            if cursor is not None:
                try:
                    window = client.get_recent(limit=2000, since_seq=cursor["latest_seq"], stream_id=cursor.get("stream_id", ""))
                    window["events"] = [event for event in window.get("events",[]) if isinstance(event,dict)
                        and str(event.get("package", "")).split(":",1)[0] == state["package"]]
                    receipt["event_integrity"] = event_integrity(window,cursor["latest_seq"],cursor.get("stream_id", ""))
                    window["ui_step_index"] = index
                    window["association"] = "capture window only, not causal proof"
                    (folder/f"{index:02d}-events.json").write_text(json.dumps(window,ensure_ascii=False),encoding="utf-8")
                except Exception as exc: receipt["event_capture_error"] = safe_error(exc)
        if not receipt["ok"]: break
    record["ok"] = len(record["receipts"]) == len(steps) and all(r["ok"] for r in record["receipts"])
    record["business_result_verified"] = False
    return workflow_artifacts.finish(record, folder)


def register(mcp) -> None:
    for tool in (capture_ui, replay_ui_steps): mcp.tool()(tool)
