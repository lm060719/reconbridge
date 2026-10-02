"""条件状态值静态来源识别测试。"""
from __future__ import annotations

from reconbridge_mcp import state_origin


def test_field_assignment_detects_preferences_source():
    source = """   20 | public void loadState() {
   21 |     this.premiumStatus = preferences.getBoolean("vip", false);
   22 | }
"""
    assignments = state_origin.extract_field_assignments(source, "premiumStatus")

    assert len(assignments) == 1
    assert assignments[0]["expression"] == 'preferences.getBoolean("vip", false)'
    kinds = [item["kind"] for item in assignments[0]["source_hints"]]
    assert "preferences" in kinds
    assert "method_result" in kinds


def test_field_assignment_detects_repository_user_model_source():
    source = """public void refresh() {
    premiumStatus = userRepository.getMemberInfo().isVip();
}
"""
    assignments = state_origin.extract_field_assignments(source, "premiumStatus")
    kinds = [item["kind"] for item in assignments[0]["source_hints"]]

    assert "network_or_repository" in kinds
    assert "user_or_membership_model" in kinds


def test_writer_ranking_prefers_direct_assignment_and_runtime_hit():
    writers = [
        {
            "class": "com.example.PayManager",
            "method": "unknown",
            "offset": 1,
            "runtime_confirmed": False,
            "source": {"available": True, "text": "void unknown() { log(); }"},
        },
        {
            "class": "com.example.PayManager",
            "method": "loadState",
            "offset": 2,
            "runtime_confirmed": True,
            "runtime_hits": 2,
            "source": {
                "available": True,
                "text": 'void loadState() { premiumStatus = preferences.getBoolean("vip", false); }',
            },
        },
    ]

    ranked = state_origin.rank_field_writers("premiumStatus", writers)

    assert ranked[0]["method"] == "loadState"
    assert ranked[0]["rank"] == 1
    assert ranked[0]["score"] > ranked[1]["score"]
    assert ranked[0]["best_source_hint"]["kind"] == "preferences"


def test_condition_method_return_source_is_classified():
    source = """boolean isPremiumUser() {
    return userRepository.getMemberInfo().isVip();
}
"""
    result = state_origin.analyze_condition_method_source(source)

    assert result["return_count"] == 1
    kinds = [item["kind"] for item in result["source_hints"]]
    assert "network_or_repository" in kinds
    assert "user_or_membership_model" in kinds
