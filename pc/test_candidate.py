"""候选方法排序测试。"""
from __future__ import annotations

from reconbridge_mcp import candidate, evidence


def test_candidate_ranking_prefers_xref_and_runtime_evidence():
    graph = evidence.new_graph()
    evidence.record_trace(
        graph,
        "com.example.PayManager",
        "checkVip",
        [{"class": "com.example.PayManager", "method": "checkVip"}],
    )

    ranked = candidate.rank(
        "会员",
        [
            {
                "class": "Lcom/example/PayManager;",
                "method": "openPaywall",
                "descriptor": "()V",
                "matched_string": "会员已过期",
                "_source": "string_xref",
            },
            {
                "class": "Lcom/example/PayManager;",
                "method": "checkVip",
                "descriptor": "()Z",
                "_source": "method_name",
            },
            {
                "class": "Landroid/app/Activity;",
                "method": "access$000",
                "descriptor": "()V",
                "_source": "method_name",
            },
        ],
        graph=graph,
        limit=10,
    )

    assert ranked[0]["method"] == "checkVip"
    assert ranked[0]["runtime_confirmed"] is True
    assert any("运行时" in reason for reason in ranked[0]["reasons"])

    paywall = next(item for item in ranked if item["method"] == "openPaywall")
    assert "会员已过期" in paywall["matched_strings"]
    assert any("字符串交叉引用" in reason for reason in paywall["reasons"])


def test_candidate_ranking_deduplicates_sources_and_normalizes_class():
    ranked = candidate.rank(
        "checkVip",
        [
            {
                "class": "Lcom/example/PayManager;",
                "method": "checkVip",
                "descriptor": "()Z",
                "_source": "method_name",
            },
            {
                "class": "com.example.PayManager",
                "method": "checkVip",
                "descriptor": "()Z",
                "matched_string": "checkVip",
                "_source": "string_xref",
            },
        ],
        graph={},
        limit=5,
    )

    assert len(ranked) == 1
    assert ranked[0]["class"] == "com.example.PayManager"
    assert set(ranked[0]["sources"]) == {"method_name", "string_xref"}
    assert ranked[0]["rank"] == 1


def test_normalize_class_name_handles_dex_descriptor():
    assert candidate.normalize_class_name("Lcom/example/Foo;") == "com.example.Foo"
    assert candidate.normalize_class_name("com.example.Foo") == "com.example.Foo"
