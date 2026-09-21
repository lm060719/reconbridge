"""代表调用路径运行时分析测试。"""
from __future__ import annotations

from reconbridge_mcp import runtime_path


def _path():
    return {
        "text": "A.start -> B.load -> C.check -> D.query",
        "length": 3,
        "nodes": [
            {"class": "com.example.A", "method": "start", "descriptor": "()V"},
            {"class": "com.example.B", "method": "load", "descriptor": "()V"},
            {"class": "com.example.C", "method": "check", "descriptor": "()Z"},
            {"class": "com.example.D", "method": "query", "descriptor": "()V"},
        ],
    }


def _hook_map():
    return {
        "h0": {"path_index": 0, "class": "com.example.A", "method": "start", "descriptor": "()V"},
        "h1": {"path_index": 1, "class": "com.example.B", "method": "load", "descriptor": "()V"},
        "h2": {"path_index": 2, "class": "com.example.C", "method": "check", "descriptor": "()Z"},
        "h3": {"path_index": 3, "class": "com.example.D", "method": "query", "descriptor": "()V"},
    }


def test_runtime_path_restores_order_and_deltas():
    events = [
        {"hook_id": "h3", "ts": 199, "seq": 4, "tid": 7, "phase": "before"},
        {"hook_id": "h1", "ts": 112, "seq": 2, "tid": 7, "phase": "before"},
        {"hook_id": "h0", "ts": 100, "seq": 1, "tid": 7, "phase": "before"},
        {"hook_id": "h2", "ts": 116, "seq": 3, "tid": 7, "phase": "before"},
    ]

    result = runtime_path.analyze_path(_path(), events, _hook_map())

    assert result["full_path_observed"] is True
    assert result["primary_tid"] == 7
    assert result["node_coverage"] == 1.0
    assert result["edge_coverage"] == 1.0
    assert result["ordered_indexes"] == [0, 1, 2, 3]

    deltas = [item["delta_ms"] for item in result["timeline"]]
    assert deltas == [None, 12.0, 4.0, 83.0]
    assert [edge["delta_ms"] for edge in result["edges"]] == [12.0, 4.0, 83.0]


def test_runtime_path_does_not_cross_threads_for_edges():
    events = [
        {"hook_id": "h0", "ts": 100, "seq": 1, "tid": 10},
        {"hook_id": "h1", "ts": 105, "seq": 2, "tid": 20},
        {"hook_id": "h2", "ts": 110, "seq": 3, "tid": 10},
        {"hook_id": "h3", "ts": 120, "seq": 4, "tid": 10},
    ]

    result = runtime_path.analyze_path(_path(), events, _hook_map())

    assert result["full_path_observed"] is False
    assert result["edge_coverage"] < 1.0
    assert result["edges"][0]["observed"] is False


def test_path_methods_deduplicates_and_skips_clinit():
    path = {
        "nodes": [
            {"class": "com.example.A", "method": "<clinit>"},
            {"class": "Lcom/example/A;", "method": "run", "descriptor": "()V"},
            {"class": "com.example.A", "method": "run", "descriptor": "(I)V"},
            {"class": "com.example.B", "method": "next", "descriptor": "()V"},
        ]
    }

    methods = runtime_path.path_methods(path)

    assert [(item["class"], item["method"]) for item in methods] == [
        ("com.example.A", "run"),
        ("com.example.B", "next"),
    ]
