"""A/B 场景首次分叉源码条件定位测试。"""
from __future__ import annotations

from reconbridge_mcp import branch_condition


def test_if_else_branch_maps_two_scenario_successors():
    source = """   100 | public void checkVip() {
   101 |     if (premiumStatus) {
   102 |         enterFeature();
   103 |     } else {
   104 |         showPaywall();
   105 |     }
   106 | }
"""

    ranked = branch_condition.rank_conditions(
        source,
        a_next="com.example.Paywall.showPaywall",
        b_next="com.example.Feature.enterFeature",
        class_fields=[
            {"field": "premiumStatus", "type": "Z"},
        ],
    )

    assert ranked
    top = ranked[0]
    assert top["type"] == "if"
    assert top["condition"] == "premiumStatus"
    assert top["matched_fields"] == ["premiumStatus"]
    assert top["branch_orientation"] == "a_false_b_true"
    assert top["score"] >= 120
    assert "showPaywall" in top["false_calls"]
    assert "enterFeature" in top["true_calls"]


def test_condition_method_generates_trace_probe_plan():
    source = """public void route() {
    if (isPremiumUser()) {
        enterFeature();
    } else {
        showPaywall();
    }
}
"""

    ranked = branch_condition.rank_conditions(
        source,
        a_next="showPaywall",
        b_next="enterFeature",
    )
    plan = branch_condition.build_probe_plan(
        "com.example.PayManager",
        "route",
        ranked,
    )

    assert ranked[0]["condition_calls"] == ["isPremiumUser"]
    assert any(
        item["kind"] == "condition_method"
        and item["method"] == "isPremiumUser"
        and item["tool"] == "trace_target"
        for item in plan
    )


def test_switch_branch_ranks_when_successors_are_in_different_cases():
    source = """public void route() {
    switch (memberType) {
        case FREE:
            showPaywall();
            break;
        case VIP:
            enterFeature();
            break;
        default:
            fallback();
    }
}
"""

    ranked = branch_condition.rank_conditions(
        source,
        a_next="showPaywall",
        b_next="enterFeature",
        class_fields=[{"field": "memberType", "type": "I"}],
    )

    assert ranked[0]["type"] == "switch"
    assert ranked[0]["condition"] == "memberType"
    assert ranked[0]["matched_fields"] == ["memberType"]
    assert ranked[0]["score"] >= 120


def test_ternary_is_detected():
    source = """public Object route() {
    return premiumStatus ? enterFeature() : showPaywall();
}
"""

    ranked = branch_condition.rank_conditions(
        source,
        a_next="showPaywall",
        b_next="enterFeature",
        class_fields=[{"field": "premiumStatus", "type": "Z"}],
    )

    assert any(item["type"] == "ternary" for item in ranked)


def test_probe_plan_prefers_field_and_deduplicates():
    ranked = [
        {
            "rank": 1,
            "line": 10,
            "condition": "premiumStatus && isEnabled()",
            "matched_fields": ["premiumStatus"],
            "condition_calls": ["isEnabled"],
        },
        {
            "rank": 2,
            "line": 20,
            "condition": "premiumStatus",
            "matched_fields": ["premiumStatus"],
            "condition_calls": [],
        },
    ]

    plan = branch_condition.build_probe_plan(
        "com.example.PayManager",
        "route",
        ranked,
        max_items=8,
    )

    assert len([item for item in plan if item["kind"] == "field"]) == 1
    assert len([item for item in plan if item["kind"] == "condition_method"]) == 1
