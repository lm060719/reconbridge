"""跨方法 Value Lineage 测试。"""
from __future__ import annotations

from reconbridge_mcp import investigation, value_lineage
from reconbridge_mcp import evidence


def test_resolve_call_unique_and_ambiguous():
    unique = value_lineage.resolve_call(
        "userRepository.isVipEnabled",
        [
            {
                "class": "Lcom/example/UserRepository;",
                "method": "isVipEnabled",
                "descriptor": "()Z",
            }
        ],
    )
    assert unique["resolved"]["class"] == "Lcom/example/UserRepository;"
    assert unique["ambiguous"] is False

    ambiguous = value_lineage.resolve_call(
        "helper.get",
        [
            {"class": "La/A;", "method": "get", "descriptor": "()Z"},
            {"class": "Lb/B;", "method": "get", "descriptor": "()Z"},
        ],
    )
    assert ambiguous["resolved"] is None
    assert ambiguous["ambiguous"] is True
    assert len(ambiguous["candidates"]) == 2


def test_finalize_builds_origin_to_sink_path():
    graph = value_lineage.new_graph()
    origin = value_lineage.add_node(
        graph,
        "origin",
        "preferences",
        "SharedPreferences",
        kind="preferences",
    )
    expression = value_lineage.add_node(
        graph,
        "expression",
        "expr",
        'preferences.getBoolean("vip", false)',
    )
    method = value_lineage.add_node(
        graph,
        "method",
        "Repo#isVip",
        "Repo.isVip",
    )
    field = value_lineage.add_node(
        graph,
        "field",
        "PayManager#premiumStatus",
        "PayManager.premiumStatus",
    )
    value_lineage.add_edge(graph, origin, expression, "feeds_expression")
    value_lineage.add_edge(graph, expression, method, "returns_from")
    value_lineage.add_edge(graph, method, field, "writes_field")

    result = value_lineage.finalize(graph, field)

    assert result["ok"]
    assert len(result["origin_paths"]) == 1
    assert "SharedPreferences" in result["origin_paths"][0]["text"]
    assert "PayManager.premiumStatus" in result["origin_paths"][0]["text"]


def test_field_value_lineage_recurses_through_callee_return(monkeypatch):
    monkeypatch.setattr(
        investigation,
        "load",
        lambda session_id, refresh=False: {
            "session_id": session_id,
            "evidence_graph": evidence.new_graph(),
        },
    )

    monkeypatch.setattr(
        investigation,
        "field_origin_context",
        lambda *args, **kwargs: {
            "ok": True,
            "field": {
                "class": "com.example.PayManager",
                "name": "premiumStatus",
                "type": "Z",
            },
            "writers": [
                {
                    "rank": 1,
                    "class": "com.example.PayManager",
                    "method": "loadMemberState",
                    "descriptor": "()V",
                    "offset": 12,
                    "assignments": [
                        {
                            "expression": "userRepository.isVipEnabled()",
                            "calls": ["userRepository.isVipEnabled"],
                            "source_hints": [
                                {
                                    "kind": "method_result",
                                    "confidence": 0.7,
                                    "reason": "来自方法返回值",
                                }
                            ],
                        }
                    ],
                }
            ],
        },
    )

    def fake_method_context(session_id, class_name, method_name, **kwargs):
        if method_name == "loadMemberState":
            return {
                "relations": {
                    "callees": [
                        {
                            "class": "Lcom/example/UserRepository;",
                            "method": "isVipEnabled",
                            "descriptor": "()Z",
                            "access": "public",
                        }
                    ]
                },
                "source": {
                    "available": True,
                    "text": "void loadMemberState() { premiumStatus = userRepository.isVipEnabled(); }",
                },
            }
        if method_name == "isVipEnabled":
            return {
                "relations": {"callees": []},
                "source": {
                    "available": True,
                    "path": "UserRepository.java",
                    "text": 'boolean isVipEnabled() { return preferences.getBoolean("vip", false); }',
                },
            }
        raise AssertionError(method_name)

    monkeypatch.setattr(investigation, "method_context", fake_method_context)

    result = investigation.field_value_lineage(
        "abc123abc123",
        "com.example.PayManager",
        "premiumStatus",
        writer_rank=1,
        max_depth=4,
    )

    assert result["ok"]
    assert result["writer"]["method"] == "loadMemberState"
    assert result["origin_paths"]

    texts = [path["text"] for path in result["origin_paths"]]
    assert any(
        "SharedPreferences/偏好存储" in text
        and "com.example.UserRepository.isVipEnabled" in text
        and "com.example.PayManager.loadMemberState" in text
        and "com.example.PayManager.premiumStatus" in text
        for text in texts
    )


def test_ambiguous_callee_is_reported_not_followed(monkeypatch):
    monkeypatch.setattr(
        investigation,
        "load",
        lambda session_id, refresh=False: {
            "session_id": session_id,
            "evidence_graph": evidence.new_graph(),
        },
    )
    monkeypatch.setattr(
        investigation,
        "field_origin_context",
        lambda *args, **kwargs: {
            "ok": True,
            "field": {
                "class": "com.example.PayManager",
                "name": "premiumStatus",
                "type": "Z",
            },
            "writers": [
                {
                    "rank": 1,
                    "class": "com.example.PayManager",
                    "method": "load",
                    "descriptor": "()V",
                    "offset": 1,
                    "assignments": [
                        {
                            "expression": "helper.get()",
                            "calls": ["helper.get"],
                            "source_hints": [],
                        }
                    ],
                }
            ],
        },
    )
    monkeypatch.setattr(
        investigation,
        "method_context",
        lambda *args, **kwargs: {
            "relations": {
                "callees": [
                    {"class": "La/A;", "method": "get", "descriptor": "()Z"},
                    {"class": "Lb/B;", "method": "get", "descriptor": "()Z"},
                ]
            },
            "source": {"available": True, "text": "void load() {}"},
        },
    )

    result = investigation.field_value_lineage(
        "abc123abc123",
        "com.example.PayManager",
        "premiumStatus",
    )

    assert len(result["ambiguities"]) == 1
    assert result["ambiguities"][0]["call"] == "helper.get"
