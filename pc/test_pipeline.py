"""自动 Investigation Pipeline 纯逻辑测试。"""
from __future__ import annotations

from reconbridge_mcp import pipeline


def test_plan_queries_extracts_quoted_text_and_business_terms():
    queries = pipeline.plan_queries(
        "帮我定位点击“立即开通”后会员状态判断方法",
        max_queries=5,
    )

    assert queries[0] == "立即开通"
    assert any("会员状态" in item for item in queries)
    assert len(queries) <= 5


def test_plan_queries_extracts_java_identifier():
    queries = pipeline.plan_queries(
        "找到 PayManager.checkVip 的实现逻辑",
        max_queries=4,
    )

    assert "PayManager.checkVip" in queries


def test_merge_rankings_rewards_cross_query_matches():
    rankings = [
        (
            "会员",
            [
                {
                    "class": "com.example.PayManager",
                    "method": "checkVip",
                    "descriptor": "()Z",
                    "score": 60,
                    "reasons": ["字符串交叉引用"],
                    "matched_strings": ["会员已过期"],
                    "sources": ["string_xref"],
                },
                {
                    "class": "com.example.Other",
                    "method": "showDialog",
                    "descriptor": "()V",
                    "score": 65,
                    "reasons": ["字符串交叉引用"],
                    "matched_strings": ["会员"],
                    "sources": ["string_xref"],
                },
            ],
        ),
        (
            "会员状态",
            [
                {
                    "class": "com.example.PayManager",
                    "method": "checkVip",
                    "descriptor": "()Z",
                    "score": 62,
                    "reasons": ["方法关联"],
                    "matched_strings": ["会员状态"],
                    "sources": ["method_name"],
                }
            ],
        ),
    ]

    merged = pipeline.merge_rankings(rankings, limit=10)

    assert merged[0]["method"] == "checkVip"
    assert set(merged[0]["matched_queries"]) == {"会员", "会员状态"}
    assert "会员已过期" in merged[0]["matched_strings"]
    assert merged[0]["rank"] == 1


def test_compact_candidate_drops_large_internal_fields():
    item = {
        "rank": 1,
        "class": "com.example.PayManager",
        "method": "checkVip",
        "descriptor": "()Z",
        "score": 100,
        "reasons": ["a"] * 20,
        "matched_strings": ["s"] * 20,
        "matched_queries": ["q1", "q2"],
        "sources": ["string_xref"],
        "large_internal_blob": "x" * 10000,
    }

    compact = pipeline.compact_candidate(item)

    assert "large_internal_blob" not in compact
    assert len(compact["reasons"]) <= 8
    assert len(compact["matched_strings"]) <= 5
