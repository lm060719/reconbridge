"""调用图场景采集与 A/B 分叉差异测试。"""
from __future__ import annotations

from reconbridge_mcp import scenario_path


def _graph():
    return {
        "ok": True,
        "nodes": [
            {
                "id": 1,
                "class": "Lcom/example/Entry;",
                "method": "onClick",
                "descriptor": "()V",
                "external": False,
                "is_target": False,
                "upstream_distance": 1,
                "downstream_distance": None,
            },
            {
                "id": 2,
                "class": "Lcom/example/PayManager;",
                "method": "checkVip",
                "descriptor": "()Z",
                "external": False,
                "is_target": True,
                "upstream_distance": 0,
                "downstream_distance": 0,
            },
            {
                "id": 3,
                "class": "Lcom/example/Paywall;",
                "method": "showPaywall",
                "descriptor": "()V",
                "external": False,
                "is_target": False,
                "upstream_distance": None,
                "downstream_distance": 1,
            },
            {
                "id": 4,
                "class": "Lcom/example/Feature;",
                "method": "enterFeature",
                "descriptor": "()V",
                "external": False,
                "is_target": False,
                "upstream_distance": None,
                "downstream_distance": 1,
            },
        ],
        "edges": [
            {"source": 1, "target": 2, "call_count": 1},
            {"source": 2, "target": 3, "call_count": 1},
            {"source": 2, "target": 4, "call_count": 1},
        ],
    }


def _hook_map():
    return {
        "h1": {
            "node_id": 1,
            "class": "com.example.Entry",
            "method": "onClick",
            "descriptor": "()V",
        },
        "h2": {
            "node_id": 2,
            "class": "com.example.PayManager",
            "method": "checkVip",
            "descriptor": "()Z",
        },
        "h3": {
            "node_id": 3,
            "class": "com.example.Paywall",
            "method": "showPaywall",
            "descriptor": "()V",
        },
        "h4": {
            "node_id": 4,
            "class": "com.example.Feature",
            "method": "enterFeature",
            "descriptor": "()V",
        },
    }


def _scenario(name, events):
    graph = _graph()
    hooks = list(_hook_map().values())
    return {
        "name": name,
        "graph_fingerprint": scenario_path.graph_fingerprint(graph),
        "hook_fingerprint": scenario_path.hook_fingerprint(hooks),
        "analysis": scenario_path.analyze_graph_scenario(
            graph,
            events,
            _hook_map(),
        ),
    }


def test_scenario_diff_finds_first_business_branch():
    scenario_a = _scenario(
        "非会员",
        [
            {"hook_id": "h1", "ts": 100, "seq": 1, "tid": 7},
            {"hook_id": "h2", "ts": 110, "seq": 2, "tid": 7},
            {"hook_id": "h3", "ts": 120, "seq": 3, "tid": 7},
        ],
    )
    scenario_b = _scenario(
        "会员",
        [
            {"hook_id": "h1", "ts": 100, "seq": 1, "tid": 7},
            {"hook_id": "h2", "ts": 110, "seq": 2, "tid": 7},
            {"hook_id": "h4", "ts": 125, "seq": 3, "tid": 7},
        ],
    )

    diff = scenario_path.diff_graph_scenarios(scenario_a, scenario_b)

    assert diff["ok"] is True
    assert diff["comparable"] is True
    assert diff["first_divergence"]["common_prefix"] == [
        "com.example.Entry.onClick",
        "com.example.PayManager.checkVip",
    ]
    assert diff["first_divergence"]["a_next"] == "com.example.Paywall.showPaywall"
    assert diff["first_divergence"]["b_next"] == "com.example.Feature.enterFeature"
    assert diff["only_in_a"][0]["method"] == "showPaywall"
    assert diff["only_in_b"][0]["method"] == "enterFeature"
    assert len(diff["only_edges_a"]) == 1
    assert len(diff["only_edges_b"]) == 1
    assert diff["shared_edge_timing"][0]["a_delta_ms"] == 10.0
    assert diff["shared_edge_timing"][0]["b_delta_ms"] == 10.0


def test_scenario_analysis_ignores_cross_thread_static_edge():
    graph = _graph()
    analysis = scenario_path.analyze_graph_scenario(
        graph,
        [
            {"hook_id": "h1", "ts": 100, "seq": 1, "tid": 10},
            {"hook_id": "h2", "ts": 110, "seq": 2, "tid": 20},
            {"hook_id": "h3", "ts": 120, "seq": 3, "tid": 20},
        ],
        _hook_map(),
    )

    edge_pairs = {(item["source"], item["target"]) for item in analysis["edges"]}
    assert (1, 2) not in edge_pairs
    assert (2, 3) in edge_pairs


def test_scenario_diff_rejects_different_hook_scope():
    scenario_a = _scenario("A", [])
    scenario_b = _scenario("B", [])
    scenario_b["hook_fingerprint"] = "different"

    diff = scenario_path.diff_graph_scenarios(scenario_a, scenario_b)

    assert diff["ok"] is False
    assert diff["comparable"] is False
    assert "Hook" in diff["error"]


def test_graph_methods_skips_external_by_default():
    graph = _graph()
    graph["nodes"].append(
        {
            "id": 5,
            "class": "Ljava/lang/String;",
            "method": "isEmpty",
            "descriptor": "()Z",
            "external": True,
            "is_target": False,
        }
    )

    methods = scenario_path.graph_methods(graph)

    assert all(item["class"] != "java.lang.String" for item in methods)
