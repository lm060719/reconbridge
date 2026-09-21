"""自动 Root Cause Ranking 测试。"""
from __future__ import annotations

from reconbridge_mcp import root_cause


def _path(origin_kind="preferences", confidence=0.95):
    return {
        "text": "origin -> Repo.isVipEnabled -> PayManager.loadMemberState -> premiumStatus",
        "nodes": [
            {
                "type": "origin",
                "label": "来自偏好存储",
                "kind": origin_kind,
                "confidence": confidence,
                "expression": 'preferences.getBoolean("vip", false)',
            },
            {
                "type": "expression",
                "label": 'preferences.getBoolean("vip", false)',
            },
            {
                "type": "method",
                "label": "com.example.Repo.isVipEnabled()Z",
                "class_name": "com.example.Repo",
                "method_name": "isVipEnabled",
                "descriptor": "()Z",
                "runtime_confirmed": True,
                "runtime_hits": 3,
            },
            {
                "type": "expression",
                "label": "repo.isVipEnabled()",
            },
            {
                "type": "method",
                "label": "com.example.PayManager.loadMemberState()V",
                "class_name": "com.example.PayManager",
                "method_name": "loadMemberState",
                "descriptor": "()V",
                "runtime_confirmed": True,
                "runtime_hits": 2,
            },
            {
                "type": "field",
                "label": "com.example.PayManager.premiumStatus",
                "class_name": "com.example.PayManager",
                "field_name": "premiumStatus",
                "field_type": "Z",
            },
        ],
        "relations": [
            "feeds_expression",
            "returns_from",
            "returns_into_expression",
            "assigned_by_expression",
            "writes_field",
        ],
    }


def _runtime_comparison():
    return {
        "ok": True,
        "comparable": True,
        "a_full_sequence": True,
        "b_full_sequence": True,
        "method_values": [
            {
                "path_index": 2,
                "label": "com.example.Repo.isVipEnabled()Z",
                "a_hit_count": 1,
                "b_hit_count": 1,
                "a_value": {
                    "type": "boolean",
                    "value": False,
                    "canonical": "false",
                },
                "b_value": {
                    "type": "boolean",
                    "value": True,
                    "canonical": "true",
                },
                "values_comparable": True,
                "same_value": False,
            },
            {
                "path_index": 4,
                "label": "com.example.PayManager.loadMemberState()V",
                "a_hit_count": 1,
                "b_hit_count": 1,
                "a_value": {
                    "type": "null",
                    "value": None,
                    "canonical": "null",
                },
                "b_value": {
                    "type": "null",
                    "value": None,
                    "canonical": "null",
                },
                "values_comparable": True,
                "same_value": True,
            },
        ],
        "first_stable_value_difference": {
            "path_index": 2,
            "label": "com.example.Repo.isVipEnabled()Z",
        },
        "a_writer_change": {
            "changed": False,
        },
        "b_writer_change": {
            "changed": True,
        },
    }


def test_runtime_first_difference_outranks_writer_and_static_origin():
    lineage = {
        "origin_paths": [_path()],
        "ambiguities": [],
        "unresolved_calls": [],
    }

    result = root_cause.rank_root_causes(
        lineage,
        runtime_comparison=_runtime_comparison(),
        selected_path_index=0,
        limit=5,
    )

    assert result["ok"] is True
    candidates = result["candidates"]
    assert candidates[0]["method"] == "isVipEnabled"
    assert candidates[0]["is_first_runtime_difference"] is True
    assert candidates[0]["evidence_level"] == "runtime_divergence"

    writer = next(item for item in candidates if item.get("is_writer"))
    origin = next(
        item for item in candidates
        if item.get("candidate_type") == "origin"
    )
    assert candidates[0]["score"] > writer["score"]
    assert writer["score"] > origin["score"]
    assert any(
        part["key"] == "first_stable_runtime_difference"
        for part in candidates[0]["score_breakdown"]
    )
    assert any(
        part["key"] == "writer_changed_field"
        for part in writer["score_breakdown"]
    )


def test_static_only_ranking_prefers_high_confidence_origin():
    lineage = {
        "origin_paths": [_path(confidence=0.98)],
        "ambiguities": [],
        "unresolved_calls": [],
    }
    for node in lineage["origin_paths"][0]["nodes"]:
        if node.get("type") == "method":
            node["runtime_confirmed"] = False
            node["runtime_hits"] = 0

    result = root_cause.rank_root_causes(
        lineage,
        runtime_comparison=None,
        limit=5,
    )

    assert result["quality"]["runtime_available"] is False
    assert result["candidates"][0]["candidate_type"] == "origin"
    assert result["candidates"][0]["evidence_level"] == "static_source"


def test_same_runtime_value_penalizes_method_priority():
    comparison = _runtime_comparison()
    comparison["first_stable_value_difference"] = None
    comparison["method_values"][0]["same_value"] = True
    comparison["method_values"][0]["b_value"] = comparison["method_values"][0]["a_value"]

    lineage = {
        "origin_paths": [_path()],
        "ambiguities": [],
        "unresolved_calls": [],
    }
    result = root_cause.rank_root_causes(
        lineage,
        runtime_comparison=comparison,
        limit=5,
    )

    repo = next(
        item for item in result["candidates"]
        if item.get("method") == "isVipEnabled"
    )
    assert any(
        part["key"] == "same_runtime_value"
        and part["points"] == -10
        for part in repo["score_breakdown"]
    )


def test_hypothesis_internal_generation_boosts_candidate():
    lineage = {
        "origin_paths": [_path()],
        "ambiguities": [],
        "unresolved_calls": [],
    }
    comparison = _runtime_comparison()
    key = "method:com.example.Repo#isVipEnabled()Z"

    baseline = root_cause.rank_root_causes(
        lineage,
        runtime_comparison=comparison,
        limit=5,
    )
    verified = root_cause.rank_root_causes(
        lineage,
        runtime_comparison=comparison,
        hypothesis_results={
            key: {
                "status": "internal_generation_supported",
                "score_adjustment": 30,
                "explanation": "入口一致而输出不同",
                "input_coverage_complete": True,
                "differing_inputs": [],
                "differing_outputs": [{"name": "return"}],
            }
        },
        limit=5,
    )

    assert verified["top_candidate"]["method"] == "isVipEnabled"
    assert (
        verified["top_candidate"]["score"]
        > baseline["top_candidate"]["score"]
    )
    assert (
        verified["top_candidate"]["evidence_level"]
        == "hypothesis_internal_supported"
    )


def test_hypothesis_upstream_difference_demotes_candidate():
    lineage = {
        "origin_paths": [_path()],
        "ambiguities": [],
        "unresolved_calls": [],
    }
    comparison = _runtime_comparison()
    key = "method:com.example.Repo#isVipEnabled()Z"

    result = root_cause.rank_root_causes(
        lineage,
        runtime_comparison=comparison,
        hypothesis_results={
            key: {
                "status": "upstream_input_difference",
                "score_adjustment": -30,
                "explanation": "入口参数已经不同",
                "input_coverage_complete": True,
                "differing_inputs": [{"name": "args[0]"}],
                "differing_outputs": [{"name": "return"}],
            }
        },
        limit=5,
    )

    repo = next(
        item for item in result["candidates"]
        if item.get("method") == "isVipEnabled"
    )
    assert repo["evidence_level"] == "hypothesis_upstream"
    assert any(
        part["key"] == "root_cause_hypothesis"
        and part["points"] == -30
        for part in repo["score_breakdown"]
    )
    assert "上游" in repo["next_action"]


def test_path_support_rewards_candidate_present_in_multiple_paths():
    first = _path()
    second = _path(origin_kind="network_or_repository", confidence=0.82)
    lineage = {
        "origin_paths": [first, second],
        "ambiguities": [],
        "unresolved_calls": [],
    }

    result = root_cause.rank_root_causes(lineage, limit=10)

    repo = next(
        item for item in result["candidates"]
        if item.get("method") == "isVipEnabled"
    )
    assert repo["path_support"] == 2
    assert any(
        part["key"] == "path_support"
        and part["points"] == 6
        for part in repo["score_breakdown"]
    )
