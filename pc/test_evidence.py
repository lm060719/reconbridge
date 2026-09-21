"""Evidence Graph 自动沉淀与关联查询测试。"""
from __future__ import annotations

from reconbridge_mcp import evidence


def test_search_results_build_relationship_graph():
    graph = evidence.new_graph()

    evidence.record_search(
        graph,
        "会员",
        "dex-sqlite-index",
        [
            {
                "class": "Lcom/example/PayManager;",
                "method": "openPaywall",
                "descriptor": "()V",
                "access": "private",
                "matched_string": "会员已过期",
            },
            {
                "class": "Lcom/example/PayManager;",
                "field": "premiumStatus",
                "type": "Z",
            },
        ],
    )

    summary = evidence.summary(graph)
    assert summary["node_count"] >= 4
    assert summary["relations"]["matched"] >= 2
    assert summary["relations"]["referenced_by"] == 1

    sub = evidence.subgraph(graph, focus="会员", depth=2)
    labels = {node["label"] for node in sub["nodes"]}
    assert "会员" in labels
    assert "会员已过期" in labels
    assert any("openPaywall" in label for label in labels)


def test_runtime_trace_marks_method_as_confirmed_and_deduplicates():
    graph = evidence.new_graph()
    events = [
        {
            "class": "com.example.PayManager",
            "method": "checkVip",
            "paths": [{"path": "ret.premium", "value": "true"}],
            "fields": [{"name": "premiumStatus", "value": "true"}],
            "stack": ["Caller.doWork(Caller.java:10)"],
        }
    ]

    evidence.record_trace(
        graph,
        "com.example.PayManager",
        "checkVip",
        events,
    )
    evidence.record_trace(
        graph,
        "com.example.PayManager",
        "checkVip",
        events,
    )

    explained = evidence.explain(graph, "checkVip")
    assert explained["runtime_confirmed"]
    assert any("checkVip" in item for item in explained["runtime_confirmed"])
    assert any(node.get("type") == "field" for node in explained["nodes"])
    assert any(edge.get("relation") == "observed_field" for edge in explained["edges"])

    # 重复记录同一证据不应让关系边无限增长。
    edge_keys = {
        (edge["source"], edge["target"], edge["relation"])
        for edge in graph["edges"]
    }
    assert len(edge_keys) == len(graph["edges"])


def test_method_context_records_call_graph_and_source():
    graph = evidence.new_graph()
    context = {
        "relations": {
            "callers": [
                {
                    "class": "Lcom/example/UiController;",
                    "method": "onSubscribeClick",
                    "descriptor": "()V",
                    "call_count": 2,
                }
            ],
            "callees": [
                {
                    "class": "Ljava/lang/String;",
                    "method": "isEmpty",
                    "descriptor": "()Z",
                    "call_count": 1,
                }
            ],
            "strings": ["会员已过期"],
            "class_fields": [
                {
                    "class": "Lcom/example/PayManager;",
                    "field": "premiumStatus",
                    "type": "Z",
                }
            ],
        },
        "source": {
            "available": True,
            "path": "PayManager.java",
            "declaration_line": 10,
            "start_line": 8,
            "end_line": 20,
        },
    }

    evidence.record_method_context(
        graph,
        "Lcom/example/PayManager;",
        "checkVip",
        "()Z",
        context,
    )

    assert any(edge["relation"] == "calls" for edge in graph["edges"])
    assert any(edge["relation"] == "source_context" for edge in graph["edges"])
    assert any(node.get("type") == "field" for node in graph["nodes"].values())


def test_empty_focus_returns_graph_slice():
    graph = evidence.new_graph()
    evidence.record_search(
        graph,
        "SecurityUtil",
        "dex-sqlite-index",
        [{"class": "Lcom/example/SecurityUtil;"}],
    )

    result = evidence.subgraph(graph, focus="", limit=20)
    assert result["node_count"] == 2
    assert len(result["nodes"]) == 2
