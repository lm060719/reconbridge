"""DEX SQLite 持久索引测试。"""
from __future__ import annotations

import sqlite3

from reconbridge_mcp.dex_index import (
    index_is_ready,
    index_path_for_apk,
    index_status,
    method_call_graph,
    method_relations,
    query_index,
    write_meta,
)
from reconbridge_mcp.dex_worker import _create_schema
from reconbridge_mcp.settings import settings


def _build_fake_index(apk, db_path):
    counts = {
        "classes": 1,
        "methods": 2,
        "fields": 1,
        "strings": 1,
        "string_method_xrefs": 1,
        "method_calls": 1,
    }
    with sqlite3.connect(db_path) as conn:
        _create_schema(conn)
        conn.execute("INSERT INTO classes(name) VALUES (?)", ("Lcom/example/PayManager;",))
        conn.execute(
            """
            INSERT INTO methods(class_name, method_name, descriptor, access)
            VALUES (?, ?, ?, ?)
            """,
            ("Lcom/example/PayManager;", "checkVip", "()Z", "public"),
        )
        conn.execute(
            """
            INSERT INTO methods(class_name, method_name, descriptor, access)
            VALUES (?, ?, ?, ?)
            """,
            ("Lcom/example/PayManager;", "openPaywall", "()V", "private"),
        )
        conn.execute(
            """
            INSERT INTO methods(class_name, method_name, descriptor, access)
            VALUES (?, ?, ?, ?)
            """,
            ("Lcom/example/UiController;", "onSubscribeClick", "()V", "public"),
        )
        conn.execute(
            """
            INSERT INTO fields(class_name, field_name, type)
            VALUES (?, ?, ?)
            """,
            ("Lcom/example/PayManager;", "premiumStatus", "Z"),
        )
        conn.execute("INSERT INTO strings(value) VALUES (?)", ("会员已过期",))
        string_id = conn.execute("SELECT id FROM strings").fetchone()[0]
        method_id = conn.execute(
            "SELECT id FROM methods WHERE method_name = ?",
            ("openPaywall",),
        ).fetchone()[0]
        conn.execute(
            "INSERT INTO string_method_xrefs(string_id, method_id) VALUES (?, ?)",
            (string_id, method_id),
        )
        caller_id = conn.execute(
            "SELECT id FROM methods WHERE method_name = ?",
            ("onSubscribeClick",),
        ).fetchone()[0]
        callee_id = conn.execute(
            "SELECT id FROM methods WHERE method_name = ?",
            ("checkVip",),
        ).fetchone()[0]
        conn.execute(
            """
            INSERT INTO method_calls(caller_method_id, callee_method_id, call_count)
            VALUES (?, ?, ?)
            """,
            (caller_id, callee_id, 2),
        )
        write_meta(conn, apk, counts)
        conn.commit()


def test_dex_index_supports_all_search_modes(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "workdir", tmp_path)
    apk = tmp_path / "base.apk"
    apk.write_bytes(b"fake-apk-content")
    db_path = index_path_for_apk(apk)
    _build_fake_index(apk, db_path)

    assert index_is_ready(apk)
    status = index_status(apk)
    assert status["ready"]
    assert status["methods"] == 3
    assert status["string_method_xrefs"] == 1
    assert status["method_calls"] == 1

    string_result = query_index(apk, {"find": "string", "string": "会员"})
    assert string_result["results"][0]["string"] == "会员已过期"

    class_result = query_index(apk, {"find": "class", "class_name": "PayManager"})
    assert class_result["results"][0]["class"] == "Lcom/example/PayManager;"

    field_result = query_index(apk, {"find": "field", "field_name": "premium"})
    assert field_result["results"][0]["field"] == "premiumStatus"

    method_result = query_index(apk, {"find": "method", "method_name": "checkVip"})
    assert method_result["results"][0]["method"] == "checkVip"

    xref_result = query_index(
        apk,
        {"find": "method", "using_strings": ["会员"]},
    )
    assert xref_result["results"][0]["method"] == "openPaywall"
    assert xref_result["results"][0]["matched_string"] == "会员已过期"
    assert xref_result["backend"] == "sqlite-index"


def test_method_relations_returns_callers_and_class_fields(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "workdir", tmp_path)
    apk = tmp_path / "base.apk"
    apk.write_bytes(b"fake-apk-content")
    db_path = index_path_for_apk(apk)
    _build_fake_index(apk, db_path)

    result = method_relations(
        apk,
        "com.example.PayManager",
        "checkVip",
        descriptor="()Z",
    )

    assert result["ok"]
    assert result["callers"][0]["method"] == "onSubscribeClick"
    assert result["callers"][0]["call_count"] == 2
    assert result["callees"] == []
    assert result["class_fields"][0]["field"] == "premiumStatus"


def test_method_call_graph_expands_two_layers_each_direction(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "workdir", tmp_path)
    apk = tmp_path / "base.apk"
    apk.write_bytes(b"fake-apk-content")
    db_path = index_path_for_apk(apk)
    _build_fake_index(apk, db_path)

    with sqlite3.connect(db_path) as conn:
        extra_methods = [
            ("Lcom/example/MainActivity;", "onVipClick", "()V", "public"),
            ("Lcom/example/UserRepository;", "getMemberInfo", "()V", "public"),
            ("Lcom/example/NetworkApi;", "queryVip", "()V", "public"),
        ]
        conn.executemany(
            """
            INSERT INTO methods(class_name, method_name, descriptor, access)
            VALUES (?, ?, ?, ?)
            """,
            extra_methods,
        )

        ids = {
            row[1]: row[0]
            for row in conn.execute("SELECT id, method_name FROM methods")
        }
        conn.executemany(
            """
            INSERT INTO method_calls(caller_method_id, callee_method_id, call_count)
            VALUES (?, ?, ?)
            """,
            [
                (ids["onVipClick"], ids["onSubscribeClick"], 1),
                (ids["checkVip"], ids["getMemberInfo"], 1),
                (ids["getMemberInfo"], ids["queryVip"], 1),
            ],
        )
        conn.commit()

    result = method_call_graph(
        apk,
        "com.example.PayManager",
        "checkVip",
        descriptor="()Z",
        upstream_depth=2,
        downstream_depth=2,
    )

    assert result["ok"]
    assert result["node_count"] >= 5
    assert result["edge_count"] >= 4

    texts = [item["text"] for item in result["representative_paths"]]
    assert any(
        "onVipClick" in text
        and "onSubscribeClick" in text
        and "checkVip" in text
        and "getMemberInfo" in text
        and "queryVip" in text
        for text in texts
    )


def test_dex_index_invalidates_when_apk_changes(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "workdir", tmp_path)
    apk = tmp_path / "base.apk"
    apk.write_bytes(b"v1")
    db_path = index_path_for_apk(apk)
    _build_fake_index(apk, db_path)
    assert index_is_ready(apk)

    apk.write_bytes(b"v2-longer")
    assert not index_is_ready(apk)
