import json
import shlex
import sys
import zipfile
from pathlib import Path
import pytest
from reconbridge_mcp import investigation, device_tools as device, ui_workflow as ui, async_analysis as asyncs, reports, server
from reconbridge_mcp.client import ReconError
from reconbridge_mcp.resource import LimitedProcessResult

PKG = "com.example.app"
XML = b'<hierarchy rotation="0"><node package="com.example.app" resource-id="com.example.app:id/go" text="Go" class="android.widget.Button" enabled="true" clickable="true" focused="true" bounds="[10,20][110,80]"/></hierarchy>'


@pytest.fixture
def session(tmp_path, monkeypatch):
    monkeypatch.setattr(investigation, "_ROOT", tmp_path/"sessions")
    monkeypatch.setattr(investigation, "_scan_artifacts", lambda _: {"apks":[],"libs":[],"jadx_dirs":[]})
    monkeypatch.setattr(ui.client,"get_recent",lambda **kwargs:{"latest_seq":0,"stream_id":"epoch","earliest_seq":1,
        "truncated":False,"cursor_reset":False,"events":[]})
    return investigation.create(PKG)["session_id"]


def test_tools_registered():
    names = {t.name for t in server.mcp._tool_manager.list_tools()}
    assert {"capture_ui","replay_ui_steps","configure_async_trace","correlate_async_events",
            "export_investigation_report","android_tool_status","analyze_apk_metadata","capture_perfetto"} <= names


def test_device_runner_preserves_binary_and_bounds():
    assert device.run_bytes([sys.executable,"-c","import sys;sys.stdout.buffer.write(bytes([0,255,13,10]))"]) == bytes([0,255,13,10])
    with pytest.raises(ReconError,match="output limit"):
        device.run_bytes([sys.executable,"-c","print('x'*10000)"],max_bytes=100)
    with pytest.raises(ReconError,match="timed out"):
        device.run_bytes([sys.executable,"-c","import time;time.sleep(10)"],timeout=.05)
    with pytest.raises(ReconError,match="failure"):
        device.run_bytes([sys.executable,"-c","import sys;sys.stderr.write('failure');sys.exit(1)"])


def test_remote_shell_quoting(monkeypatch):
    calls=[]
    monkeypatch.setattr(device,"adb_bytes",lambda *args,**kwargs: calls.append(args) or b"")
    device.shell("input","text","a'b;$(id)&xyz")
    assert shlex.split(calls[0][1]) == ["input","text","a'b;$(id)&xyz"]


@pytest.mark.parametrize("payload", [b"<!DOCTYPE x><hierarchy/>",b"<wrong/>",b'<hierarchy><node package="other.app"/></hierarchy>'])
def test_ui_invalid_inputs(payload):
    with pytest.raises(ValueError): ui.parse_hierarchy(payload,PKG)


def test_ui_ambiguous_selector_and_plan_validation(session, monkeypatch):
    tree=ui.parse_hierarchy(XML,PKG)
    tree["nodes"] *= 2
    with pytest.raises(ValueError,match="exactly one"): ui.select_node(tree,{"text":"Go"},PKG)
    monkeypatch.setattr(ui,"snapshot",lambda *a,**k: pytest.fail("preview must not contact device"))
    assert ui.replay_ui_steps(session,[{"action":"tap","selector":{"text":"Go"}}])["executed"] is False
    with pytest.raises(ValueError): ui.replay_ui_steps(session,[{"action":"tap","selector":{"text":"Go"}},{"action":"shell"}],True)
    with pytest.raises(ValueError): ui.validate_steps([{"action":"text","selector":{"text":"Go"},"text":"%s"}])


def test_ui_record_replay_and_stop_on_stale_precondition(session,monkeypatch):
    tree=ui.parse_hierarchy(XML,PKG)
    monkeypatch.setattr(ui,"snapshot",lambda *a,**k:(tree,XML,None))
    calls=[]
    monkeypatch.setattr(device,"shell",lambda *a,**k:calls.append(a) or b"")
    result=ui.replay_ui_steps(session,[{"action":"tap","selector":{"text":"Go"}}, {"action":"assert","selector":{"text":"Go"}}],True)
    assert result["ok"] and calls == [("input","tap","60","50")]
    assert "00-before.json" in result["files"] and "01-after.json" in result["files"]
    assert "00-events.json" in result["files"] and result["receipts"][0]["event_integrity"]["complete"]
    calls.clear()
    result=ui.replay_ui_steps(session,[{"action":"tap","selector":{"text":"Go"},"expected_hierarchy_sha256":"0"*64}],True)
    assert not result["ok"] and not calls and not result["receipts"][0]["input_attempted"]


def test_ui_uncertain_input_is_not_retried(session,monkeypatch):
    tree=ui.parse_hierarchy(XML,PKG)
    monkeypatch.setattr(ui,"snapshot",lambda *a,**k:(tree,XML,None))
    calls=[]
    def fail(*args,**kwargs):
        calls.append(args); raise ReconError("timeout")
    monkeypatch.setattr(device,"shell",fail)
    result=ui.replay_ui_steps(session,[{"action":"tap","selector":{"text":"Go"}}]*2,True)
    assert len(calls)==1 and result["receipts"][0]["effect_unknown"]


def test_snapshot_screenshot_and_cleanup(session,monkeypatch):
    calls=[]
    monkeypatch.setattr(device,"shell",lambda *a,**k:calls.append(a) or b"")
    monkeypatch.setattr(device,"adb_bytes",lambda *a,**k: XML if a[1]=="cat" else b"\x89PNG\r\n\x1a\npayload")
    result=ui.capture_ui(session)
    assert result["ok"] and "screenshot.png" in result["files"]
    assert calls[-1][:2] == ("rm","-f")


def test_perfetto_capture_and_cleanup(session,monkeypatch):
    calls=[]
    monkeypatch.setattr(device,"shell",lambda *a,**k:calls.append((a,k)) or b"")
    monkeypatch.setattr(device,"adb_bytes",lambda *a,**k:b"trace")
    result=device.capture_perfetto(session,seconds=2)
    assert result["ok"] and "trace.perfetto-trace" in result["files"]
    assert calls[0][0][0]=="perfetto" and calls[-1][0][:2]==("rm","-f")
    with pytest.raises(ValueError): device.capture_perfetto(session,seconds=61)


def event(span,role,phase="after",instance="instance",**extra):
    return {"package":PKG,"pid":42,"process_instance":instance,"seq":int(span),"stream_id":"epoch","phase":phase,
        "correlation":{"version":1,"span_id":span,"async":{"role":role,"namespace":"tasks","task_id":"ticket",**extra}}}


def test_async_explicit_identity_not_timestamps(session):
    enqueue=event("1","enqueue",enqueue_returned_successfully=True)
    execute=event("2","execute",status="matched",enqueue_span_id="1")
    result=asyncs.correlate_async_events(session,[execute,enqueue])
    assert result["edge_count"]==1 and result["analysis"]["complete"] is None
    execute["process_instance"]="other-process"
    assert not asyncs.correlate([enqueue,execute],PKG)["edges"]
    execute["process_instance"]="instance"
    execute["correlation"]["async"]["status"]="ambiguous"
    assert len(asyncs.correlate([enqueue,execute],PKG)["unresolved"])==1
    execute["correlation"]["async"]["status"]="matched"
    enqueue["correlation"]["async"]["enqueue_returned_successfully"]=False
    assert not asyncs.correlate([enqueue,execute],PKG)["edges"]


def test_async_config_is_explicit_append(monkeypatch):
    calls=[]
    monkeypatch.setattr(asyncs.client,"post_json",lambda path,body: calls.append((path,body)) or {"ok":True})
    result=asyncs.configure_async_trace(PKG,{"class":"app.Queue","method":"enqueue","task":"arg:0"},{"class":"app.Task","method":"run"})
    assert calls[0][1]["mode"]=="append" and calls[0][1]["targets"][1]["async_link"]["task"]=="this"
    assert result["runtime_effect_confirmed"] is False
    with pytest.raises(ValueError): asyncs.configure_async_trace(PKG,{"class":"A","method":"x","task":"ret"},{"class":"B","method":"run"})


def test_apkanalyzer_discovery_and_fixed_commands(tmp_path,monkeypatch):
    executable=tmp_path/"apkanalyzer"; executable.write_text("fixture")
    apk=tmp_path/"sample.apk"; apk.write_bytes(b"apk")
    monkeypatch.setenv("RECONBRIDGE_APKANALYZER",str(executable))
    calls=[]
    monkeypatch.setattr(device,"run_limited",lambda command,**kwargs:calls.append(command) or LimitedProcessResult(0,"manifest",False,False))
    assert device.analyze_apk_metadata(str(apk),"manifest")["ok"]
    assert calls[0][1:3]==["manifest","print"]
    with pytest.raises(ValueError): device.analyze_apk_metadata(str(apk),"shell")


def test_report_redaction_escaping_hashes_and_binary_exclusion(session,monkeypatch):
    folder=investigation._session_path(session).with_suffix(".workflow")/"example"
    folder.mkdir(parents=True)
    (folder/"record.json").write_text(json.dumps({"kind":"<script>alert(1)</script>","token":"secret","args":["private"],"ok":True}))
    (folder/"screenshot.png").write_bytes(b"raw secret")
    monkeypatch.setattr(reports.external,"toolchain_status",lambda:{"ready":True})
    result=reports.export_investigation_report(session)
    page=Path(result["report_html"]).read_text(encoding="utf-8")
    assert "<script>alert" not in page and "&lt;script&gt;" in page
    with zipfile.ZipFile(result["support_bundle"]) as archive:
        assert not any(name.endswith(".png") for name in archive.namelist())
        saved=archive.read("workflow/example/record.json").decode()
        assert "secret" not in saved and "private" not in saved
        manifest=json.loads(archive.read("manifest.json"))
        import hashlib
        for name,entry in manifest["files"].items(): assert hashlib.sha256(archive.read(name)).hexdigest()==entry["sha256"]
    assert result["uploaded"] is False and result["complete"] is None
