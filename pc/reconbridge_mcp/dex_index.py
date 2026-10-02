"""APK DEX 持久索引。

首次由受资源限制的 Androguard worker 建库；后续搜索、字符串 xref 和方法调用关系
全部直接查询 SQLite，不再重复解析 APK。
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any

from .settings import settings

SCHEMA_VERSION = 3


def apk_cache_key(apk: Path) -> str:
    stat = apk.stat()
    raw = f"{apk.resolve()}|{stat.st_size}|{stat.st_mtime_ns}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:24]


def index_path_for_apk(apk_path: str | Path) -> Path:
    apk = Path(apk_path)
    root = settings.workdir / ".index" / "dex"
    root.mkdir(parents=True, exist_ok=True)
    return root / f"{apk_cache_key(apk)}.sqlite3"


def index_is_ready(apk_path: str | Path) -> bool:
    apk = Path(apk_path)
    if not apk.exists():
        return False
    path = index_path_for_apk(apk)
    if not path.exists():
        return False

    try:
        with sqlite3.connect(path) as conn:
            rows = dict(conn.execute("SELECT key, value FROM meta"))
        stat = apk.stat()
        return (
            int(rows.get("schema_version", "0")) == SCHEMA_VERSION
            and int(rows.get("apk_size", "-1")) == stat.st_size
            and int(rows.get("apk_mtime_ns", "-1")) == stat.st_mtime_ns
            and rows.get("complete") == "1"
        )
    except (OSError, sqlite3.Error, ValueError):
        return False


def index_status(apk_path: str | Path) -> dict[str, Any]:
    apk = Path(apk_path)
    path = index_path_for_apk(apk) if apk.exists() else None
    result: dict[str, Any] = {
        "ready": bool(apk.exists() and index_is_ready(apk)),
        "path": str(path) if path else "",
        "bytes": path.stat().st_size if path and path.exists() else 0,
        "schema_version": SCHEMA_VERSION,
    }
    if not result["ready"]:
        return result

    try:
        with sqlite3.connect(path) as conn:
            for table in (
                "classes",
                "methods",
                "fields",
                "strings",
                "string_method_xrefs",
                "method_calls",
                "field_reads",
                "field_writes",
            ):
                result[table] = int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
    except sqlite3.Error:
        result["ready"] = False
    return result


def _like_term(value: str) -> str:
    return f"%{value}%"


def _class_variants(class_name: str) -> list[str]:
    value = (class_name or "").strip()
    if not value:
        return [""]
    variants = [value]
    if value.startswith("L") and value.endswith(";"):
        dotted = value[1:-1].replace("/", ".")
        if dotted not in variants:
            variants.append(dotted)
    elif "/" in value:
        descriptor = value if value.startswith("L") else f"L{value};"
        dotted = value.strip("L;").replace("/", ".")
        for item in (descriptor, dotted):
            if item not in variants:
                variants.append(item)
    else:
        descriptor = "L" + value.replace(".", "/") + ";"
        if descriptor not in variants:
            variants.append(descriptor)
    return variants


def _method_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "class": row["class_name"],
        "method": row["method_name"],
        "descriptor": row["descriptor"],
        "access": row["access"],
    }


def query_index(apk_path: str | Path, query: dict[str, Any]) -> dict[str, Any]:
    apk = Path(apk_path)
    if not index_is_ready(apk):
        return {"ok": False, "error": "DEX 持久索引尚未建立"}

    path = index_path_for_apk(apk)
    find = str(query.get("find", "method"))
    limit = max(1, min(int(query.get("max_results", 100)), 5000))
    results: list[dict[str, Any]] = []

    with sqlite3.connect(path) as conn:
        conn.row_factory = sqlite3.Row

        if find == "string":
            term = str(query.get("string", ""))
            rows = conn.execute(
                """
                SELECT value
                FROM strings
                WHERE value LIKE ? ESCAPE '\\'
                ORDER BY length(value), value
                LIMIT ?
                """,
                (_like_term(term), limit),
            )
            results = [{"string": row["value"]} for row in rows]

        elif find == "class":
            term = str(query.get("class_name", ""))
            rows = conn.execute(
                """
                SELECT name
                FROM classes
                WHERE name LIKE ? ESCAPE '\\'
                ORDER BY length(name), name
                LIMIT ?
                """,
                (_like_term(term), limit),
            )
            results = [{"class": row["name"]} for row in rows]

        elif find == "field":
            class_term = str(query.get("class_name", ""))
            field_term = str(query.get("field_name", ""))
            rows = conn.execute(
                """
                SELECT class_name, field_name, type
                FROM fields
                WHERE class_name LIKE ? ESCAPE '\\'
                  AND field_name LIKE ? ESCAPE '\\'
                ORDER BY class_name, field_name
                LIMIT ?
                """,
                (_like_term(class_term), _like_term(field_term), limit),
            )
            results = [
                {"class": row["class_name"], "field": row["field_name"], "type": row["type"]}
                for row in rows
            ]

        else:
            using = query.get("using_strings")
            if using:
                seen: set[tuple[str, str, str]] = set()
                for keyword in using:
                    rows = conn.execute(
                        """
                        SELECT m.class_name, m.method_name, m.descriptor, m.access, s.value
                        FROM strings s
                        JOIN string_method_xrefs x ON x.string_id = s.id
                        JOIN methods m ON m.id = x.method_id
                        WHERE s.value LIKE ? ESCAPE '\\'
                        ORDER BY m.class_name, m.method_name
                        LIMIT ?
                        """,
                        (_like_term(str(keyword)), limit * 4),
                    )
                    for row in rows:
                        key = (row["class_name"], row["method_name"], row["descriptor"])
                        if key in seen:
                            continue
                        seen.add(key)
                        results.append({
                            "class": row["class_name"],
                            "method": row["method_name"],
                            "descriptor": row["descriptor"],
                            "access": row["access"],
                            "matched_string": row["value"],
                            "matched_query": keyword,
                        })
                        if len(results) >= limit:
                            break
                    if len(results) >= limit:
                        break
            else:
                class_term = str(query.get("class_name", ""))
                method_term = str(query.get("method_name", ""))
                rows = conn.execute(
                    """
                    SELECT class_name, method_name, descriptor, access
                    FROM methods
                    WHERE class_name LIKE ? ESCAPE '\\'
                      AND method_name LIKE ? ESCAPE '\\'
                    ORDER BY class_name, method_name, descriptor
                    LIMIT ?
                    """,
                    (_like_term(class_term), _like_term(method_term), limit),
                )
                results = [_method_dict(row) for row in rows]

    return {
        "ok": True,
        "backend": "sqlite-index",
        "find": find,
        "count": len(results),
        "results": results,
        "index_path": str(path),
        "cache_hit": True,
    }


def method_relations(
    apk_path: str | Path,
    class_name: str,
    method_name: str,
    descriptor: str = "",
    limit: int = 30,
) -> dict[str, Any]:
    """返回一个方法的调用者、被调用方法、关联字符串和同类字段。"""
    apk = Path(apk_path)
    if not index_is_ready(apk):
        return {"ok": False, "error": "DEX 持久索引尚未建立"}

    limit = max(1, min(int(limit), 100))
    path = index_path_for_apk(apk)
    variants = _class_variants(class_name)
    placeholders = ",".join("?" for _ in variants)
    params: list[Any] = [*variants, method_name]
    descriptor_sql = ""
    if descriptor:
        descriptor_sql = " AND descriptor = ?"
        params.append(descriptor)

    with sqlite3.connect(path) as conn:
        conn.row_factory = sqlite3.Row
        targets = list(
            conn.execute(
                f"""
                SELECT id, class_name, method_name, descriptor, access
                FROM methods
                WHERE class_name IN ({placeholders})
                  AND method_name = ?
                  {descriptor_sql}
                ORDER BY descriptor
                LIMIT 20
                """,
                params,
            )
        )
        if not targets:
            return {
                "ok": False,
                "error": "索引中找不到目标方法",
                "class": class_name,
                "method": method_name,
                "descriptor": descriptor,
            }

        target_ids = [int(row["id"]) for row in targets]
        target_placeholders = ",".join("?" for _ in target_ids)

        callers = list(
            conn.execute(
                f"""
                SELECT DISTINCT m.class_name, m.method_name, m.descriptor, m.access,
                       SUM(c.call_count) AS call_count
                FROM method_calls c
                JOIN methods m ON m.id = c.caller_method_id
                WHERE c.callee_method_id IN ({target_placeholders})
                GROUP BY m.class_name, m.method_name, m.descriptor, m.access
                ORDER BY call_count DESC, m.class_name, m.method_name
                LIMIT ?
                """,
                [*target_ids, limit],
            )
        )
        callees = list(
            conn.execute(
                f"""
                SELECT DISTINCT m.class_name, m.method_name, m.descriptor, m.access,
                       SUM(c.call_count) AS call_count
                FROM method_calls c
                JOIN methods m ON m.id = c.callee_method_id
                WHERE c.caller_method_id IN ({target_placeholders})
                GROUP BY m.class_name, m.method_name, m.descriptor, m.access
                ORDER BY call_count DESC, m.class_name, m.method_name
                LIMIT ?
                """,
                [*target_ids, limit],
            )
        )
        strings = list(
            conn.execute(
                f"""
                SELECT DISTINCT s.value
                FROM string_method_xrefs x
                JOIN strings s ON s.id = x.string_id
                WHERE x.method_id IN ({target_placeholders})
                ORDER BY length(s.value), s.value
                LIMIT ?
                """,
                [*target_ids, limit],
            )
        )

        class_variants: list[str] = []
        for row in targets:
            for value in _class_variants(str(row["class_name"])):
                if value not in class_variants:
                    class_variants.append(value)
        class_placeholders = ",".join("?" for _ in class_variants)
        fields = list(
            conn.execute(
                f"""
                SELECT class_name, field_name, type
                FROM fields
                WHERE class_name IN ({class_placeholders})
                ORDER BY field_name
                LIMIT ?
                """,
                [*class_variants, limit],
            )
        )

    return {
        "ok": True,
        "backend": "sqlite-index",
        "targets": [_method_dict(row) for row in targets],
        "callers": [
            {**_method_dict(row), "call_count": int(row["call_count"] or 0)}
            for row in callers
        ],
        "callees": [
            {**_method_dict(row), "call_count": int(row["call_count"] or 0)}
            for row in callees
        ],
        "strings": [row["value"] for row in strings],
        "class_fields": [
            {
                "class": row["class_name"],
                "field": row["field_name"],
                "type": row["type"],
            }
            for row in fields
        ],
        "index_path": str(path),
    }


def field_relations(
    apk_path: str | Path,
    class_name: str,
    field_name: str,
    field_type: str = "",
    limit: int = 100,
) -> dict[str, Any]:
    """返回字段定义，以及所有静态读取/写入它的方法和 DEX offset。"""
    apk = Path(apk_path)
    if not index_is_ready(apk):
        return {"ok": False, "error": "DEX 持久索引尚未建立"}

    limit = max(1, min(int(limit), 500))
    path = index_path_for_apk(apk)
    variants = _class_variants(class_name)
    placeholders = ",".join("?" for _ in variants)
    params: list[Any] = [*variants, field_name]
    type_sql = ""
    if field_type:
        type_sql = " AND type = ?"
        params.append(field_type)

    with sqlite3.connect(path) as conn:
        conn.row_factory = sqlite3.Row
        targets = list(
            conn.execute(
                f"""
                SELECT id, class_name, field_name, type
                FROM fields
                WHERE class_name IN ({placeholders})
                  AND field_name = ?
                  {type_sql}
                ORDER BY type
                LIMIT 20
                """,
                params,
            )
        )
        if not targets:
            return {
                "ok": False,
                "error": "索引中找不到目标字段",
                "class": class_name,
                "field": field_name,
                "type": field_type,
            }

        field_ids = [int(row["id"]) for row in targets]
        ph = ",".join("?" for _ in field_ids)

        def load_access(table: str) -> list[dict[str, Any]]:
            rows = conn.execute(
                f"""
                SELECT m.class_name, m.method_name, m.descriptor, m.access,
                       x.offset
                FROM {table} x
                JOIN methods m ON m.id = x.method_id
                WHERE x.field_id IN ({ph})
                ORDER BY m.class_name, m.method_name, x.offset
                LIMIT ?
                """,
                [*field_ids, limit],
            )
            return [
                {
                    **_method_dict(row),
                    "offset": int(row["offset"] or 0),
                }
                for row in rows
            ]

        readers = load_access("field_reads")
        writers = load_access("field_writes")

    return {
        "ok": True,
        "backend": "sqlite-index",
        "fields": [
            {
                "class": row["class_name"],
                "field": row["field_name"],
                "type": row["type"],
            }
            for row in targets
        ],
        "readers": readers,
        "writers": writers,
        "reader_count": len(readers),
        "writer_count": len(writers),
        "index_path": str(path),
    }


def _is_external_class(class_name: str) -> bool:
    value = class_name.replace("/", ".")
    if value.startswith("L"):
        value = value[1:]
    return value.startswith((
        "java.",
        "javax.",
        "android.",
        "androidx.",
        "kotlin.",
        "kotlinx.",
        "dalvik.",
        "sun.",
        "org.jetbrains.",
    ))


def method_call_graph(
    apk_path: str | Path,
    class_name: str,
    method_name: str,
    descriptor: str = "",
    upstream_depth: int = 2,
    downstream_depth: int = 2,
    max_nodes: int = 120,
    max_edges: int = 300,
    max_paths: int = 20,
    expand_external: bool = False,
) -> dict[str, Any]:
    """围绕目标方法递归展开调用图，并给出代表性的上下游路径。"""
    apk = Path(apk_path)
    if not index_is_ready(apk):
        return {"ok": False, "error": "DEX 持久索引尚未建立"}

    upstream_depth = max(0, min(int(upstream_depth), 5))
    downstream_depth = max(0, min(int(downstream_depth), 5))
    max_nodes = max(10, min(int(max_nodes), 500))
    max_edges = max(20, min(int(max_edges), 1500))
    max_paths = max(1, min(int(max_paths), 100))
    path = index_path_for_apk(apk)

    variants = _class_variants(class_name)
    placeholders = ",".join("?" for _ in variants)
    params: list[Any] = [*variants, method_name]
    descriptor_sql = ""
    if descriptor:
        descriptor_sql = " AND descriptor = ?"
        params.append(descriptor)

    with sqlite3.connect(path) as conn:
        conn.row_factory = sqlite3.Row
        targets = list(
            conn.execute(
                f"""
                SELECT id, class_name, method_name, descriptor, access
                FROM methods
                WHERE class_name IN ({placeholders})
                  AND method_name = ?
                  {descriptor_sql}
                ORDER BY descriptor
                LIMIT 20
                """,
                params,
            )
        )
        if not targets:
            return {
                "ok": False,
                "error": "索引中找不到目标方法",
                "class": class_name,
                "method": method_name,
                "descriptor": descriptor,
            }

        nodes: dict[int, dict[str, Any]] = {}
        edges: dict[tuple[int, int], dict[str, Any]] = {}
        target_ids = [int(row["id"]) for row in targets]

        def add_node(row: sqlite3.Row, *, up: int | None = None, down: int | None = None) -> int:
            node_id = int(row["id"])
            node = nodes.get(node_id)
            if node is None:
                if len(nodes) >= max_nodes:
                    return node_id
                node = {
                    "id": node_id,
                    "class": row["class_name"],
                    "method": row["method_name"],
                    "descriptor": row["descriptor"],
                    "access": row["access"],
                    "external": _is_external_class(str(row["class_name"])),
                    "upstream_distance": None,
                    "downstream_distance": None,
                    "is_target": node_id in target_ids,
                }
                nodes[node_id] = node
            if up is not None:
                old = node.get("upstream_distance")
                if old is None or up < old:
                    node["upstream_distance"] = up
            if down is not None:
                old = node.get("downstream_distance")
                if old is None or down < old:
                    node["downstream_distance"] = down
            return node_id

        for row in targets:
            add_node(row, up=0, down=0)

        up_paths: dict[int, list[int]] = {target_id: [target_id] for target_id in target_ids}
        down_paths: dict[int, list[int]] = {target_id: [target_id] for target_id in target_ids}

        def expand(direction: str, depth: int) -> None:
            frontier = list(target_ids)
            for level in range(1, depth + 1):
                if not frontier or len(nodes) >= max_nodes or len(edges) >= max_edges:
                    break
                ph = ",".join("?" for _ in frontier)

                if direction == "up":
                    rows = list(
                        conn.execute(
                            f"""
                            SELECT c.caller_method_id AS src_id,
                                   c.callee_method_id AS dst_id,
                                   c.call_count,
                                   m.id, m.class_name, m.method_name, m.descriptor, m.access
                            FROM method_calls c
                            JOIN methods m ON m.id = c.caller_method_id
                            WHERE c.callee_method_id IN ({ph})
                            ORDER BY c.call_count DESC, m.class_name, m.method_name
                            """,
                            frontier,
                        )
                    )
                else:
                    rows = list(
                        conn.execute(
                            f"""
                            SELECT c.caller_method_id AS src_id,
                                   c.callee_method_id AS dst_id,
                                   c.call_count,
                                   m.id, m.class_name, m.method_name, m.descriptor, m.access
                            FROM method_calls c
                            JOIN methods m ON m.id = c.callee_method_id
                            WHERE c.caller_method_id IN ({ph})
                            ORDER BY c.call_count DESC, m.class_name, m.method_name
                            """,
                            frontier,
                        )
                    )

                next_frontier: list[int] = []
                for row in rows:
                    if len(edges) >= max_edges:
                        break
                    src_id = int(row["src_id"])
                    dst_id = int(row["dst_id"])
                    discovered_id = int(row["id"])

                    if discovered_id not in nodes and len(nodes) >= max_nodes:
                        continue
                    add_node(
                        row,
                        up=level if direction == "up" else None,
                        down=level if direction == "down" else None,
                    )
                    edges[(src_id, dst_id)] = {
                        "source": src_id,
                        "target": dst_id,
                        "call_count": int(row["call_count"] or 0),
                    }

                    discovered = nodes.get(discovered_id)
                    if discovered is None:
                        continue

                    if direction == "up":
                        base = up_paths.get(dst_id)
                        if base and discovered_id not in up_paths:
                            up_paths[discovered_id] = [discovered_id, *base]
                    else:
                        base = down_paths.get(src_id)
                        if base and discovered_id not in down_paths:
                            down_paths[discovered_id] = [*base, discovered_id]

                    if discovered["external"] and not expand_external:
                        continue
                    if discovered_id not in next_frontier:
                        next_frontier.append(discovered_id)

                frontier = next_frontier

        expand("up", upstream_depth)
        expand("down", downstream_depth)

    def public_node(node_id: int) -> dict[str, Any]:
        node = nodes[node_id]
        return {
            "id": node_id,
            "class": node["class"],
            "method": node["method"],
            "descriptor": node["descriptor"],
            "access": node["access"],
            "external": node["external"],
            "is_target": node["is_target"],
            "upstream_distance": node["upstream_distance"],
            "downstream_distance": node["downstream_distance"],
        }

    def path_payload(ids: list[int]) -> dict[str, Any]:
        path_nodes = [public_node(node_id) for node_id in ids if node_id in nodes]
        return {
            "length": max(0, len(path_nodes) - 1),
            "nodes": path_nodes,
            "text": " -> ".join(
                f"{item['class']}.{item['method']}"
                for item in path_nodes
            ),
        }

    upstream_paths = [
        path_payload(ids)
        for node_id, ids in up_paths.items()
        if node_id not in target_ids and len(ids) > 1
    ]
    downstream_paths = [
        path_payload(ids)
        for node_id, ids in down_paths.items()
        if node_id not in target_ids and len(ids) > 1
    ]
    upstream_paths.sort(key=lambda item: (-item["length"], item["text"]))
    downstream_paths.sort(key=lambda item: (-item["length"], item["text"]))

    # 把一条上游路径与一条下游路径通过 target 拼起来，形成“入口 → 目标 → 下游”的代表链。
    combined_paths: list[dict[str, Any]] = []
    for up in upstream_paths[: max_paths]:
        up_nodes = up["nodes"]
        target_id = next((item["id"] for item in reversed(up_nodes) if item["is_target"]), None)
        if target_id is None:
            continue
        matching_down = [
            item
            for item in downstream_paths
            if item["nodes"] and item["nodes"][0]["id"] == target_id
        ]
        if matching_down:
            for down in matching_down[:3]:
                ids = [item["id"] for item in up_nodes]
                ids.extend(item["id"] for item in down["nodes"][1:])
                combined_paths.append(path_payload(ids))
        else:
            combined_paths.append(up)
        if len(combined_paths) >= max_paths:
            break

    if not upstream_paths:
        combined_paths.extend(downstream_paths[:max_paths])

    unique_combined: list[dict[str, Any]] = []
    seen_text: set[str] = set()
    for item in combined_paths:
        if item["text"] in seen_text:
            continue
        seen_text.add(item["text"])
        unique_combined.append(item)
        if len(unique_combined) >= max_paths:
            break

    return {
        "ok": True,
        "backend": "sqlite-index",
        "targets": [public_node(target_id) for target_id in target_ids if target_id in nodes],
        "node_count": len(nodes),
        "edge_count": len(edges),
        "nodes": [public_node(node_id) for node_id in nodes],
        "edges": list(edges.values()),
        "upstream_paths": upstream_paths[:max_paths],
        "downstream_paths": downstream_paths[:max_paths],
        "representative_paths": unique_combined,
        "limits": {
            "upstream_depth": upstream_depth,
            "downstream_depth": downstream_depth,
            "max_nodes": max_nodes,
            "max_edges": max_edges,
            "expand_external": expand_external,
        },
        "index_path": str(path),
    }


def write_meta(conn: sqlite3.Connection, apk: Path, counts: dict[str, int]) -> None:
    stat = apk.stat()
    meta = {
        "schema_version": str(SCHEMA_VERSION),
        "apk_path": str(apk.resolve()),
        "apk_size": str(stat.st_size),
        "apk_mtime_ns": str(stat.st_mtime_ns),
        "counts": json.dumps(counts, ensure_ascii=False, sort_keys=True),
        "complete": "1",
    }
    conn.executemany(
        "INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)",
        meta.items(),
    )
