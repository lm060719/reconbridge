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


def test_call_graph_runtime_annotation_marks_paths():
    graph = evidence.new_graph()
    evidence.record_trace(
        graph,
        "com.example.PayManager",
        "checkVip",
        [{"class": "com.example.PayManager", "method": "checkVip"}],
    )
    evidence.record_trace(
        graph,
        "com.example.UserRepository",
        "getMemberInfo",
        [{"class": "com.example.UserRepository", "method": "getMemberInfo"}],
    )

    call_graph = {
        "ok": True,
        "nodes": [
            {
                "id": 1,
                "class": "Lcom/example/PayManager;",
                "method": "checkVip",
                "descriptor": "()Z",
                "access": "public",
            },
            {
                "id": 2,
                "class": "Lcom/example/UserRepository;",
                "method": "getMemberInfo",
                "descriptor": "()V",
                "access": "public",
            },
        ],
        "edges": [{"source": 1, "target": 2, "call_count": 1}],
        "upstream_paths": [],
        "downstream_paths": [
            {
                "length": 1,
                "nodes": [
                    {"id": 1, "class": "Lcom/example/PayManager;", "method": "checkVip"},
                    {"id": 2, "class": "Lcom/example/UserRepository;", "method": "getMemberInfo"},
                ],
                "text": "checkVip -> getMemberInfo",
            }
        ],
        "representative_paths": [
            {
                "length": 1,
                "nodes": [
                    {"id": 1, "class": "Lcom/example/PayManager;", "method": "checkVip"},
                    {"id": 2, "class": "Lcom/example/UserRepository;", "method": "getMemberInfo"},
                ],
                "text": "checkVip -> getMemberInfo",
            }
        ],
    }

    evidence.annotate_call_graph_runtime(graph, call_graph)

    assert call_graph["runtime_confirmed_nodes"] == 2
    assert call_graph["representative_paths"][0]["runtime_confirmed_nodes"] == 2
    assert call_graph["representative_paths"][0]["runtime_coverage"] == 1.0
    assert call_graph["edges"][0]["runtime_observed"] is True


def test_runtime_path_records_observed_sequence_edges():
    graph = evidence.new_graph()
    path = {
        "nodes": [
            {"class": "com.example.A", "method": "start", "descriptor": "()V"},
            {"class": "com.example.B", "method": "load", "descriptor": "()V"},
        ]
    }
    analysis = {
        "node_hits": [
            {"path_index": 0, "hits": 1},
            {"path_index": 1, "hits": 1},
        ],
        "edges": [
            {
                "source_index": 0,
                "target_index": 1,
                "observed": True,
                "delta_ms": 12.0,
            }
        ],
    }

    evidence.record_runtime_path(graph, path, analysis)

    runtime_edges = [
        edge for edge in graph["edges"]
        if edge.get("relation") == "runtime_sequence"
    ]
    assert len(runtime_edges) == 1
    assert runtime_edges[0]["delta_ms"] == 12.0


def test_field_origin_records_writer_reader_and_source_nodes():
    graph = evidence.new_graph()
    context = {
        "ok": True,
        "field": {
            "class": "com.example.PayManager",
            "name": "premiumStatus",
            "type": "Z",
        },
        "writers": [
            {
                "class": "com.example.PayManager",
                "method": "loadState",
                "descriptor": "()V",
                "offset": 12,
                "rank": 1,
                "runtime_confirmed": True,
                "runtime_hits": 2,
                "assignments": [
                    {
                        "expression": 'preferences.getBoolean("vip", false)',
                        "source_hints": [
                            {
                                "kind": "preferences",
                                "confidence": 0.95,
                                "reason": "来自偏好存储",
                            }
                        ],
                    }
                ],
            }
        ],
        "readers": [
            {
                "class": "com.example.PayManager",
                "method": "checkVip",
                "descriptor": "()Z",
                "offset": 24,
            }
        ],
    }

    evidence.record_field_origin(graph, context)

    relations = {edge["relation"] for edge in graph["edges"]}
    assert "writes_field" in relations
    assert "read_by" in relations
    assert "feeds_writer" in relations
    assert any(
        node.get("type") == "state_origin"
        and node.get("kind") == "preferences"
        for node in graph["nodes"].values()
    )


def test_value_lineage_is_persisted_into_evidence_graph():
    graph = evidence.new_graph()
    lineage = {
        "ok": True,
        "nodes": [
            {
                "id": "origin:1",
                "type": "origin",
                "label": "来自偏好存储",
                "kind": "preferences",
                "confidence": 0.95,
            },
            {
                "id": "expr:1",
                "type": "expression",
                "label": 'preferences.getBoolean("vip", false)',
                "owner_class": "com.example.UserRepository",
                "owner_method": "isVipEnabled",
            },
            {
                "id": "method:1",
                "type": "method",
                "label": "com.example.UserRepository.isVipEnabled",
                "class_name": "com.example.UserRepository",
                "method_name": "isVipEnabled",
                "descriptor": "()Z",
            },
            {
                "id": "field:1",
                "type": "field",
                "label": "com.example.PayManager.premiumStatus",
                "class_name": "com.example.PayManager",
                "field_name": "premiumStatus",
                "field_type": "Z",
            },
        ],
        "edges": [
            {
                "source": "origin:1",
                "target": "expr:1",
                "relation": "feeds_expression",
            },
            {
                "source": "expr:1",
                "target": "method:1",
                "relation": "returns_from",
            },
            {
                "source": "method:1",
                "target": "field:1",
                "relation": "writes_field",
            },
        ],
    }

    evidence.record_value_lineage(graph, lineage)

    relations = {edge["relation"] for edge in graph["edges"]}
    assert "feeds_expression" in relations
    assert "returns_from" in relations
    assert "writes_field" in relations
    assert any(
        node.get("type") == "value_expression"
        for node in graph["nodes"].values()
    )


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
