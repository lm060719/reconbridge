"""Runtime Value Lineage 多方法采集与 A/B 比较测试。"""
from __future__ import annotations

from reconbridge_mcp import runtime_lineage


def _path():
    return {
        "text": (
            "Preferences -> Repo.isVipEnabled -> "
            "PayManager.loadMemberState -> PayManager.premiumStatus"
        ),
        "length": 5,
        "nodes": [
            {
                "id": "origin:1",
                "type": "origin",
                "label": "Preferences",
                "kind": "preferences",
            },
            {
                "id": "expr:1",
                "type": "expression",
                "label": 'preferences.getBoolean("vip", false)',
            },
            {
                "id": "method:1",
                "type": "method",
                "label": "com.example.Repo.isVipEnabled()Z",
                "class_name": "com.example.Repo",
                "method_name": "isVipEnabled",
                "descriptor": "()Z",
            },
            {
                "id": "expr:2",
                "type": "expression",
                "label": "repo.isVipEnabled()",
            },
            {
                "id": "method:2",
                "type": "method",
                "label": "com.example.PayManager.loadMemberState()V",
                "class_name": "com.example.PayManager",
                "method_name": "loadMemberState",
                "descriptor": "()V",
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
        "relations": [
            "feeds_expression",
            "returns_from",
            "returns_into_expression",
            "assigned_by_expression",
            "writes_field",
        ],
    }


def _hook_map():
    return {
        "h1": {
            "path_index": 2,
            "class": "com.example.Repo",
            "method": "isVipEnabled",
            "descriptor": "()Z",
            "label": "com.example.Repo.isVipEnabled()Z",
        },
        "h2": {
            "path_index": 4,
            "class": "com.example.PayManager",
            "method": "loadMemberState",
            "descriptor": "()V",
            "label": "com.example.PayManager.loadMemberState()V",
        },
    }


def test_runtime_lineage_restores_return_order_and_writer_change():
    events = [
        {
            "hook_id": "h2",
            "phase": "before",
            "ts": 105,
            "seq": 2,
            "tid": 7,
            "fields": [
                {"name": "premiumStatus", "value": "false"}
            ],
        },
        {
            "hook_id": "h1",
            "phase": "after",
            "ts": 100,
            "seq": 1,
            "tid": 7,
            "ret": True,
        },
        {
            "hook_id": "h2",
            "phase": "after",
            "ts": 120,
            "seq": 3,
            "tid": 7,
            "ret": None,
            "fields": [
                {"name": "premiumStatus", "value": "true"}
            ],
        },
    ]

    result = runtime_lineage.analyze_capture(
        _path(),
        events,
        _hook_map(),
    )

    assert result["method_coverage"] == 1.0
    assert result["ordered_coverage"] == 1.0
    assert result["full_method_sequence_observed"] is True
    assert result["primary_tid"] == 7
    assert [item["path_index"] for item in result["timeline"]] == [2, 4]
    assert result["timeline"][1]["delta_ms"] == 20.0
    assert result["observations"][0]["returns"]["stable_value"]["value"] is True
    assert result["writer_change"]["changed"] is True
    assert result["writer_change"]["distinct_changes"][0]["before"]["value"] is False
    assert result["writer_change"]["distinct_changes"][0]["after"]["value"] is True


def test_runtime_lineage_path_methods_skips_external_by_default():
    path = _path()
    path["nodes"].insert(
        2,
        {
            "id": "method:java",
            "type": "method",
            "label": "java.lang.Boolean.booleanValue()Z",
            "class_name": "java.lang.Boolean",
            "method_name": "booleanValue",
            "descriptor": "()Z",
        },
    )

    methods = runtime_lineage.path_methods(path)

    assert all(item["class"] != "java.lang.Boolean" for item in methods)
    assert [item["method"] for item in methods] == [
        "isVipEnabled",
        "loadMemberState",
    ]


def _capture(name, repo_value, writer_value):
    path = _path()
    return {
        "scenario": name,
        "lineage_fingerprint": runtime_lineage.path_fingerprint(path),
        "analysis": {
            "full_method_sequence_observed": True,
            "method_coverage": 1.0,
            "observations": [
                {
                    "path_index": 2,
                    "label": "com.example.Repo.isVipEnabled()Z",
                    "hit_count": 1,
                    "returns": {
                        "stable": True,
                        "stable_value": {
                            "type": "boolean",
                            "value": repo_value,
                            "canonical": "true" if repo_value else "false",
                        },
                    },
                },
                {
                    "path_index": 4,
                    "label": "com.example.PayManager.loadMemberState()V",
                    "hit_count": 1,
                    "returns": {
                        "stable": True,
                        "stable_value": {
                            "type": "null",
                            "value": None,
                            "canonical": "null",
                        },
                    },
                },
            ],
            "writer_change": {
                "changed": True,
                "distinct_changes": [
                    {
                        "before": {
                            "type": "boolean",
                            "value": not writer_value,
                            "canonical": "false" if writer_value else "true",
                        },
                        "after": {
                            "type": "boolean",
                            "value": writer_value,
                            "canonical": "true" if writer_value else "false",
                        },
                    }
                ],
            },
        },
    }


def test_runtime_lineage_comparison_finds_first_stable_difference():
    result = runtime_lineage.compare_captures(
        _capture("非会员", False, False),
        _capture("会员", True, True),
    )

    assert result["ok"] is True
    assert result["a_full_sequence"] is True
    assert result["b_full_sequence"] is True
    first = result["first_stable_value_difference"]
    assert first["path_index"] == 2
    assert first["label"] == "com.example.Repo.isVipEnabled()Z"
    assert first["a_value"]["value"] is False
    assert first["b_value"]["value"] is True


def test_runtime_lineage_comparison_rejects_different_paths():
    left = _capture("A", False, False)
    right = _capture("B", True, True)
    right["lineage_fingerprint"] = "different"

    result = runtime_lineage.compare_captures(left, right)

    assert result["ok"] is False
    assert result["comparable"] is False
