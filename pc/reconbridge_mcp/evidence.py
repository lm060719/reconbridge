"""分析会话 Evidence Graph。

把静态搜索、字符串 xref、源码命中和运行时 trace 自动沉淀为轻量证据图。
图保存在 investigation 会话 JSON 中，不依赖额外数据库。
"""
from __future__ import annotations

import hashlib
from collections import deque
from typing import Any

MAX_NODES = 1500
MAX_EDGES = 5000


def new_graph() -> dict[str, Any]:
    return {"nodes": {}, "edges": []}


def _hash(value: str) -> str:
    return hashlib.sha1(value.encode("utf-8", errors="replace")).hexdigest()[:16]


def _ensure(graph: dict[str, Any]) -> dict[str, Any]:
    graph.setdefault("nodes", {})
    graph.setdefault("edges", [])
    return graph


def add_node(
    graph: dict[str, Any],
    node_id: str,
    node_type: str,
    label: str,
    **attrs: Any,
) -> str:
    _ensure(graph)
    nodes = graph["nodes"]
    node = nodes.get(node_id)
    if node is None:
        if len(nodes) >= MAX_NODES:
            return node_id
        node = {"id": node_id, "type": node_type, "label": label}
        nodes[node_id] = node
    for key, value in attrs.items():
        if value not in (None, "", [], {}):
            node[key] = value
    return node_id


def add_edge(
    graph: dict[str, Any],
    source: str,
    target: str,
    relation: str,
    **attrs: Any,
) -> None:
    _ensure(graph)
    edges = graph["edges"]
    key = (source, target, relation)
    for edge in edges:
        if (edge.get("source"), edge.get("target"), edge.get("relation")) == key:
            for name, value in attrs.items():
                if value not in (None, "", [], {}):
                    edge[name] = value
            return
    if len(edges) >= MAX_EDGES:
        return
    edge = {"source": source, "target": target, "relation": relation}
    for name, value in attrs.items():
        if value not in (None, "", [], {}):
            edge[name] = value
    edges.append(edge)


def query_node(graph: dict[str, Any], query: str, strategy: str = "") -> str:
    return add_node(
        graph,
        f"query:{_hash(query)}",
        "query",
        query,
        strategy=strategy,
    )


def string_node(graph: dict[str, Any], value: str) -> str:
    return add_node(graph, f"string:{_hash(value)}", "string", value[:500], value=value[:2000])


def class_node(graph: dict[str, Any], class_name: str) -> str:
    return add_node(graph, f"class:{class_name}", "class", class_name)


def method_node(
    graph: dict[str, Any],
    class_name: str,
    method_name: str,
    descriptor: str = "",
    **attrs: Any,
) -> str:
    suffix = descriptor or ""
    label = f"{class_name}.{method_name}{suffix}"
    node_id = add_node(
        graph,
        f"method:{class_name}#{method_name}{suffix}",
        "method",
        label,
        class_name=class_name,
        method_name=method_name,
        descriptor=descriptor,
        **attrs,
    )
    if class_name:
        cid = class_node(graph, class_name)
        add_edge(graph, cid, node_id, "contains")
    return node_id


def field_node(
    graph: dict[str, Any],
    class_name: str,
    field_name: str,
    field_type: str = "",
) -> str:
    node_id = add_node(
        graph,
        f"field:{class_name}#{field_name}",
        "field",
        f"{class_name}.{field_name}",
        class_name=class_name,
        field_name=field_name,
        field_type=field_type,
    )
    if class_name:
        cid = class_node(graph, class_name)
        add_edge(graph, cid, node_id, "contains")
    return node_id


def origin_node(
    graph: dict[str, Any],
    kind: str,
    label: str,
    **attrs: Any,
) -> str:
    return add_node(
        graph,
        f"origin:{kind}:{_hash(label)}",
        "state_origin",
        label,
        kind=kind,
        **attrs,
    )


def source_node(graph: dict[str, Any], path: str, line: int) -> str:
    return add_node(
        graph,
        f"source:{_hash(path)}:{line}",
        "source",
        f"{path}:{line}",
        path=path,
        line=line,
    )


def record_search(
    graph: dict[str, Any],
    query: str,
    strategy: str,
    results: list[dict[str, Any]],
) -> None:
    qid = query_node(graph, query, strategy)
    for result in results:
        if "method" in result:
            class_name = str(result.get("class", ""))
            method_name = str(result.get("method", ""))
            descriptor = str(result.get("descriptor", ""))
            mid = method_node(
                graph,
                class_name,
                method_name,
                descriptor,
                access=result.get("access", ""),
            )
            add_edge(graph, qid, mid, "matched")

            matched_values: list[str] = []
            matched_string = result.get("matched_string")
            if matched_string:
                matched_values.append(str(matched_string))
            for value in result.get("matched_strings") or []:
                value = str(value)
                if value and value not in matched_values:
                    matched_values.append(value)

            for matched_value in matched_values[:12]:
                sid = string_node(graph, matched_value)
                add_edge(graph, qid, sid, "led_to")
                add_edge(graph, sid, mid, "referenced_by")

        elif "field" in result:
            fid = field_node(
                graph,
                str(result.get("class", "")),
                str(result.get("field", "")),
                str(result.get("type", "")),
            )
            add_edge(graph, qid, fid, "matched")

        elif "class" in result:
            cid = class_node(graph, str(result.get("class", "")))
            add_edge(graph, qid, cid, "matched")

        elif "string" in result:
            sid = string_node(graph, str(result.get("string", "")))
            add_edge(graph, qid, sid, "matched")

        elif "path" in result:
            src = source_node(
                graph,
                str(result.get("path", "")),
                int(result.get("line", 0) or 0),
            )
            add_edge(graph, qid, src, "source_hit", snippet=str(result.get("text", ""))[:500])


def record_trace(
    graph: dict[str, Any],
    class_name: str,
    method_name: str,
    events: list[dict[str, Any]],
) -> None:
    mid = method_node(
        graph,
        class_name,
        method_name,
        runtime_hits=len(events),
        runtime_confirmed=bool(events),
    )
    runtime_id = add_node(
        graph,
        f"runtime:{_hash(class_name + '#' + method_name)}",
        "runtime",
        f"运行时命中 {class_name}.{method_name}",
        hits=len(events),
    )
    add_edge(graph, mid, runtime_id, "runtime_observed", hits=len(events))

    for event in events[:100]:
        event_class = str(event.get("class") or class_name)
        event_method = str(event.get("method") or method_name)
        event_mid = method_node(graph, event_class, event_method, runtime_confirmed=True)
        add_edge(graph, mid, event_mid, "runtime_event")

        for path in event.get("paths") or []:
            path_name = str(path.get("path", ""))
            if not path_name:
                continue
            pid = add_node(
                graph,
                f"path:{event_mid}:{_hash(path_name)}",
                "path",
                path_name,
                value=str(path.get("value", ""))[:1000],
                unresolved=bool(path.get("unresolved")),
            )
            add_edge(graph, event_mid, pid, "observed_path")

        for field in event.get("fields") or []:
            field_name = str(field.get("name", ""))
            if not field_name:
                continue
            fid = field_node(graph, event_class, field_name)
            add_edge(
                graph,
                event_mid,
                fid,
                "observed_field",
                value=str(field.get("value", ""))[:1000],
            )

        stack = event.get("stack") or []
        previous = event_mid
        if isinstance(stack, list):
            for frame in stack[:12]:
                label = str(frame)
                if not label:
                    continue
                fid = add_node(
                    graph,
                    f"frame:{_hash(label)}",
                    "stack_frame",
                    label[:500],
                )
                add_edge(graph, previous, fid, "called_from")
                previous = fid


def record_method_context(
    graph: dict[str, Any],
    class_name: str,
    method_name: str,
    descriptor: str,
    context: dict[str, Any],
) -> None:
    """把静态调用关系、字符串、字段与源码位置写入 Evidence Graph。"""
    mid = method_node(graph, class_name, method_name, descriptor)
    relations = context.get("relations") or {}

    for caller in relations.get("callers") or []:
        caller_id = method_node(
            graph,
            str(caller.get("class", "")),
            str(caller.get("method", "")),
            str(caller.get("descriptor", "")),
            access=caller.get("access", ""),
        )
        add_edge(
            graph,
            caller_id,
            mid,
            "calls",
            call_count=int(caller.get("call_count", 0) or 0),
        )

    for callee in relations.get("callees") or []:
        callee_id = method_node(
            graph,
            str(callee.get("class", "")),
            str(callee.get("method", "")),
            str(callee.get("descriptor", "")),
            access=callee.get("access", ""),
        )
        add_edge(
            graph,
            mid,
            callee_id,
            "calls",
            call_count=int(callee.get("call_count", 0) or 0),
        )

    for value in relations.get("strings") or []:
        sid = string_node(graph, str(value))
        add_edge(graph, sid, mid, "referenced_by")

    for field in relations.get("class_fields") or []:
        field_node(
            graph,
            str(field.get("class", class_name)),
            str(field.get("field", "")),
            str(field.get("type", "")),
        )

    source = context.get("source") or {}
    if source.get("available") and source.get("path"):
        sid = source_node(
            graph,
            str(source["path"]),
            int(source.get("declaration_line", 0) or 0),
        )
        add_edge(
            graph,
            mid,
            sid,
            "source_context",
            start_line=int(source.get("start_line", 0) or 0),
            end_line=int(source.get("end_line", 0) or 0),
        )


def _normalize_method_class(class_name: str) -> str:
    value = (class_name or "").strip()
    if value.startswith("L") and value.endswith(";"):
        value = value[1:-1]
    return value.replace("/", ".")


def runtime_method_stats(graph: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    """汇总 Evidence Graph 中已有的运行时方法证据，忽略 descriptor 差异。"""
    _ensure(graph)
    stats: dict[tuple[str, str], dict[str, Any]] = {}

    for node in graph["nodes"].values():
        if node.get("type") != "method":
            continue
        class_name = _normalize_method_class(str(node.get("class_name", "")))
        method_name = str(node.get("method_name", ""))
        if not class_name or not method_name:
            continue

        key = (class_name, method_name)
        slot = stats.setdefault(
            key,
            {
                "runtime_confirmed": False,
                "runtime_hits": 0,
                "labels": [],
            },
        )
        slot["runtime_confirmed"] = bool(
            slot["runtime_confirmed"] or node.get("runtime_confirmed")
        )
        slot["runtime_hits"] = max(
            int(slot["runtime_hits"]),
            int(node.get("runtime_hits", 0) or 0),
        )
        label = str(node.get("label", ""))
        if label and label not in slot["labels"]:
            slot["labels"].append(label)

    return stats


def annotate_call_graph_runtime(
    graph: dict[str, Any],
    call_graph: dict[str, Any],
) -> dict[str, Any]:
    """把 Evidence Graph 的 runtime 命中信息叠加到静态调用图和代表路径。"""
    if not call_graph.get("ok"):
        return call_graph

    stats = runtime_method_stats(graph)
    node_runtime: dict[int, dict[str, Any]] = {}

    for node in call_graph.get("nodes") or []:
        key = (
            _normalize_method_class(str(node.get("class", ""))),
            str(node.get("method", "")),
        )
        runtime = stats.get(
            key,
            {"runtime_confirmed": False, "runtime_hits": 0, "labels": []},
        )
        node["runtime_confirmed"] = bool(runtime["runtime_confirmed"])
        node["runtime_hits"] = int(runtime["runtime_hits"])
        node_runtime[int(node["id"])] = runtime

    for edge in call_graph.get("edges") or []:
        source = node_runtime.get(int(edge.get("source", -1)), {})
        target = node_runtime.get(int(edge.get("target", -1)), {})
        edge["runtime_observed"] = bool(
            source.get("runtime_confirmed") and target.get("runtime_confirmed")
        )

    for field in ("upstream_paths", "downstream_paths", "representative_paths"):
        for path in call_graph.get(field) or []:
            confirmed = 0
            hits = 0
            for node in path.get("nodes") or []:
                runtime = node_runtime.get(int(node.get("id", -1)), {})
                node["runtime_confirmed"] = bool(runtime.get("runtime_confirmed"))
                node["runtime_hits"] = int(runtime.get("runtime_hits", 0) or 0)
                if node["runtime_confirmed"]:
                    confirmed += 1
                    hits += node["runtime_hits"]
            path["runtime_confirmed_nodes"] = confirmed
            path["runtime_hits"] = hits
            path["runtime_coverage"] = (
                round(confirmed / len(path.get("nodes") or []), 3)
                if path.get("nodes")
                else 0.0
            )

    call_graph["runtime_confirmed_nodes"] = sum(
        1 for node in call_graph.get("nodes") or []
        if node.get("runtime_confirmed")
    )
    return call_graph


def record_call_graph(
    graph: dict[str, Any],
    call_graph: dict[str, Any],
) -> None:
    """把递归调用图写回 Evidence Graph，供后续调查继续复用。"""
    if not call_graph.get("ok"):
        return

    id_to_evidence: dict[int, str] = {}
    for node in (call_graph.get("nodes") or [])[:400]:
        node_id = method_node(
            graph,
            str(node.get("class", "")),
            str(node.get("method", "")),
            str(node.get("descriptor", "")),
            access=node.get("access", ""),
            runtime_confirmed=bool(node.get("runtime_confirmed")),
            runtime_hits=int(node.get("runtime_hits", 0) or 0),
        )
        id_to_evidence[int(node["id"])] = node_id

    for edge in (call_graph.get("edges") or [])[:1200]:
        source = id_to_evidence.get(int(edge.get("source", -1)))
        target = id_to_evidence.get(int(edge.get("target", -1)))
        if not source or not target:
            continue
        add_edge(
            graph,
            source,
            target,
            "calls",
            call_count=int(edge.get("call_count", 0) or 0),
            runtime_observed=bool(edge.get("runtime_observed")),
        )


def record_runtime_path(
    graph: dict[str, Any],
    path: dict[str, Any],
    analysis: dict[str, Any],
) -> None:
    """把一次代表路径动态验证结果写入 Evidence Graph。"""
    static_nodes = path.get("nodes") or []
    by_index = {
        index: node
        for index, node in enumerate(static_nodes)
    }

    # 命中的节点标记 runtime_confirmed，并累加本轮命中次数。
    for hit in analysis.get("node_hits") or []:
        index = int(hit.get("path_index", -1))
        count = int(hit.get("hits", 0) or 0)
        node = by_index.get(index)
        if not node or count <= 0:
            continue
        mid = method_node(
            graph,
            str(node.get("class", "")),
            str(node.get("method", "")),
            str(node.get("descriptor", "")),
            runtime_confirmed=True,
        )
        existing = graph["nodes"].get(mid, {})
        existing["runtime_hits"] = max(
            int(existing.get("runtime_hits", 0) or 0),
            count,
        )

    # 静态相邻边一旦在时间线上按序观测到，额外记录 runtime_sequence。
    for edge in analysis.get("edges") or []:
        if not edge.get("observed"):
            continue
        source = by_index.get(int(edge.get("source_index", -1)))
        target = by_index.get(int(edge.get("target_index", -1)))
        if not source or not target:
            continue
        source_id = method_node(
            graph,
            str(source.get("class", "")),
            str(source.get("method", "")),
            str(source.get("descriptor", "")),
            runtime_confirmed=True,
        )
        target_id = method_node(
            graph,
            str(target.get("class", "")),
            str(target.get("method", "")),
            str(target.get("descriptor", "")),
            runtime_confirmed=True,
        )
        add_edge(
            graph,
            source_id,
            target_id,
            "runtime_sequence",
            delta_ms=edge.get("delta_ms"),
        )


def record_field_origin(
    graph: dict[str, Any],
    context: dict[str, Any],
) -> None:
    """把字段 writer/reader 与可能来源写入 Evidence Graph。"""
    if not context.get("ok"):
        return
    field = context.get("field") or {}
    class_name = str(field.get("class", ""))
    field_name = str(field.get("name", ""))
    field_type = str(field.get("type", ""))
    if not field_name:
        return

    fid = field_node(graph, class_name, field_name, field_type)

    for writer in (context.get("writers") or [])[:100]:
        mid = method_node(
            graph,
            str(writer.get("class", "")),
            str(writer.get("method", "")),
            str(writer.get("descriptor", "")),
            access=writer.get("access", ""),
            runtime_confirmed=bool(writer.get("runtime_confirmed")),
            runtime_hits=int(writer.get("runtime_hits", 0) or 0),
        )
        add_edge(
            graph,
            mid,
            fid,
            "writes_field",
            offset=int(writer.get("offset", 0) or 0),
            writer_rank=int(writer.get("rank", 0) or 0),
        )

        for assignment in (writer.get("assignments") or [])[:12]:
            for hint in (assignment.get("source_hints") or [])[:4]:
                kind = str(hint.get("kind", "unknown"))
                label = str(hint.get("reason") or kind)
                oid = origin_node(
                    graph,
                    kind,
                    label,
                    confidence=float(hint.get("confidence", 0) or 0),
                    expression=str(assignment.get("expression", ""))[:1000],
                )
                add_edge(
                    graph,
                    oid,
                    mid,
                    "feeds_writer",
                    field=field_name,
                    expression=str(assignment.get("expression", ""))[:1000],
                )

    for reader in (context.get("readers") or [])[:100]:
        mid = method_node(
            graph,
            str(reader.get("class", "")),
            str(reader.get("method", "")),
            str(reader.get("descriptor", "")),
            access=reader.get("access", ""),
            runtime_confirmed=bool(reader.get("runtime_confirmed")),
            runtime_hits=int(reader.get("runtime_hits", 0) or 0),
        )
        add_edge(
            graph,
            fid,
            mid,
            "read_by",
            offset=int(reader.get("offset", 0) or 0),
        )


def record_value_lineage(
    graph: dict[str, Any],
    lineage: dict[str, Any],
) -> None:
    """把跨方法 Value Lineage 图写入 Evidence Graph。"""
    if not lineage.get("ok"):
        return

    id_map: dict[str, str] = {}
    for node in (lineage.get("nodes") or [])[:300]:
        node_type = str(node.get("type", ""))
        source_id = str(node.get("id", ""))
        if not source_id:
            continue

        if node_type == "method":
            target_id = method_node(
                graph,
                str(node.get("class_name", "")),
                str(node.get("method_name", "")),
                str(node.get("descriptor", "")),
                runtime_confirmed=bool(node.get("runtime_confirmed")),
                runtime_hits=int(node.get("runtime_hits", 0) or 0),
            )
        elif node_type == "field":
            target_id = field_node(
                graph,
                str(node.get("class_name", "")),
                str(node.get("field_name", "")),
                str(node.get("field_type", "")),
            )
        elif node_type == "origin":
            target_id = origin_node(
                graph,
                str(node.get("kind", "unknown")),
                str(node.get("label", "来源")),
                confidence=float(node.get("confidence", 0) or 0),
                expression=str(node.get("expression", ""))[:1000],
            )
        elif node_type == "expression":
            target_id = add_node(
                graph,
                f"value_expr:{_hash(str(node.get('label', '')) + source_id)}",
                "value_expression",
                str(node.get("label", ""))[:500],
                owner_class=node.get("owner_class", ""),
                owner_method=node.get("owner_method", ""),
                line_offset=node.get("line_offset"),
            )
        else:
            target_id = add_node(
                graph,
                f"lineage:{_hash(source_id)}",
                f"value_{node_type or 'node'}",
                str(node.get("label", ""))[:500],
            )
        id_map[source_id] = target_id

    for edge in (lineage.get("edges") or [])[:1200]:
        source = id_map.get(str(edge.get("source", "")))
        target = id_map.get(str(edge.get("target", "")))
        if not source or not target:
            continue
        attrs = {
            key: value
            for key, value in edge.items()
            if key not in {"source", "target", "relation"}
        }
        add_edge(
            graph,
            source,
            target,
            str(edge.get("relation", "value_flow")),
            **attrs,
        )


def record_runtime_lineage(
    graph: dict[str, Any],
    path: dict[str, Any],
    analysis: dict[str, Any],
) -> None:
    """把 Runtime Value Lineage 的真实返回顺序和值摘要写入证据图。"""
    nodes = path.get("nodes") or []
    method_ids: dict[int, str] = {}

    for observation in analysis.get("observations") or []:
        path_index = int(observation.get("path_index", -1))
        if not (0 <= path_index < len(nodes)):
            continue
        node = nodes[path_index]
        returns = observation.get("returns") or {}
        stable_value = returns.get("stable_value") or {}
        preview = str(stable_value.get("canonical", ""))[:500]

        mid = method_node(
            graph,
            str(node.get("class_name", observation.get("class", ""))),
            str(node.get("method_name", observation.get("method", ""))),
            str(node.get("descriptor", observation.get("descriptor", ""))),
            runtime_confirmed=bool(observation.get("hit_count")),
            runtime_hits=int(observation.get("hit_count", 0) or 0),
            runtime_return_stable=bool(returns.get("stable")),
            runtime_return_type=stable_value.get("type", ""),
            runtime_return_preview=preview,
        )
        method_ids[path_index] = mid

    timeline = analysis.get("timeline") or []
    for source, target in zip(timeline, timeline[1:]):
        source_id = method_ids.get(int(source.get("path_index", -1)))
        target_id = method_ids.get(int(target.get("path_index", -1)))
        if not source_id or not target_id:
            continue
        add_edge(
            graph,
            source_id,
            target_id,
            "runtime_value_sequence",
            delta_ms=target.get("delta_ms"),
            tid=target.get("tid"),
        )

    field = analysis.get("terminal_field") or {}
    writer_change = analysis.get("writer_change") or {}
    if field and writer_change:
        field_id = field_node(
            graph,
            str(field.get("class", "")),
            str(field.get("field", "")),
            str(field.get("type", "")),
        )
        method_indexes = sorted(method_ids)
        if method_indexes:
            writer_id = method_ids[method_indexes[-1]]
            distinct = writer_change.get("distinct_changes") or []
            first_change = distinct[0] if distinct else {}
            add_edge(
                graph,
                writer_id,
                field_id,
                "runtime_writes_field",
                changed=bool(writer_change.get("changed")),
                changed_calls=int(writer_change.get("changed_calls", 0) or 0),
                before=(
                    (first_change.get("before") or {}).get("canonical")
                    if first_change
                    else None
                ),
                after=(
                    (first_change.get("after") or {}).get("canonical")
                    if first_change
                    else None
                ),
            )


def record_root_cause_ranking(
    graph: dict[str, Any],
    ranking: dict[str, Any],
) -> None:
    """把根因排序结果回写到对应方法/来源节点。"""
    if not ranking.get("ok"):
        return

    for candidate in (ranking.get("candidates") or [])[:20]:
        candidate_type = str(candidate.get("candidate_type", ""))
        attrs = {
            "root_cause_rank": int(candidate.get("rank", 0) or 0),
            "root_cause_score": int(candidate.get("score", 0) or 0),
            "root_cause_raw_score": int(candidate.get("raw_score", 0) or 0),
            "root_cause_evidence_level": str(
                candidate.get("evidence_level", "")
            ),
            "root_cause_reasons": [
                str(item.get("reason", ""))
                for item in (candidate.get("score_breakdown") or [])[:10]
                if item.get("reason")
            ],
            "root_cause_next_action": str(
                candidate.get("next_action", "")
            )[:1000],
        }

        if candidate_type == "method":
            method_node(
                graph,
                str(candidate.get("class", "")),
                str(candidate.get("method", "")),
                str(candidate.get("descriptor", "")),
                **attrs,
            )
        elif candidate_type == "origin":
            origin_node(
                graph,
                str(candidate.get("kind", "unknown")),
                str(candidate.get("label", "来源")),
                confidence=float(candidate.get("confidence", 0) or 0),
                expression=str(candidate.get("expression", ""))[:1000],
                **attrs,
            )


def summary(graph: dict[str, Any]) -> dict[str, Any]:
    _ensure(graph)
    type_counts: dict[str, int] = {}
    relation_counts: dict[str, int] = {}
    for node in graph["nodes"].values():
        node_type = str(node.get("type", "unknown"))
        type_counts[node_type] = type_counts.get(node_type, 0) + 1
    for edge in graph["edges"]:
        relation = str(edge.get("relation", "unknown"))
        relation_counts[relation] = relation_counts.get(relation, 0) + 1
    return {
        "node_count": len(graph["nodes"]),
        "edge_count": len(graph["edges"]),
        "node_types": type_counts,
        "relations": relation_counts,
    }


def subgraph(
    graph: dict[str, Any],
    focus: str = "",
    depth: int = 2,
    limit: int = 100,
) -> dict[str, Any]:
    _ensure(graph)
    depth = max(0, min(int(depth), 5))
    limit = max(1, min(int(limit), 300))
    nodes = graph["nodes"]
    edges = graph["edges"]

    if not focus:
        selected_ids = list(nodes.keys())[:limit]
    else:
        needle = focus.casefold()
        seeds = [
            node_id
            for node_id, node in nodes.items()
            if needle in str(node.get("label", "")).casefold()
            or needle in node_id.casefold()
        ][:20]
        selected: set[str] = set(seeds)
        queue = deque((node_id, 0) for node_id in seeds)
        adjacency: dict[str, list[str]] = {}
        for edge in edges:
            adjacency.setdefault(str(edge["source"]), []).append(str(edge["target"]))
            adjacency.setdefault(str(edge["target"]), []).append(str(edge["source"]))

        while queue and len(selected) < limit:
            current, level = queue.popleft()
            if level >= depth:
                continue
            for neighbor in adjacency.get(current, []):
                if neighbor in selected:
                    continue
                selected.add(neighbor)
                queue.append((neighbor, level + 1))
                if len(selected) >= limit:
                    break
        selected_ids = list(selected)

    selected_set = set(selected_ids)
    out_nodes = [nodes[node_id] for node_id in selected_ids if node_id in nodes]
    out_edges = [
        edge
        for edge in edges
        if edge.get("source") in selected_set and edge.get("target") in selected_set
    ][: limit * 3]

    return {
        **summary(graph),
        "focus": focus,
        "depth": depth,
        "nodes": out_nodes,
        "edges": out_edges,
    }


def explain(graph: dict[str, Any], focus: str, depth: int = 3, limit: int = 80) -> dict[str, Any]:
    data = subgraph(graph, focus=focus, depth=depth, limit=limit)
    nodes = data["nodes"]
    edges = data["edges"]
    runtime_methods = [
        node["label"]
        for node in nodes
        if node.get("type") == "method" and node.get("runtime_confirmed")
    ]
    strings = [node["label"] for node in nodes if node.get("type") == "string"]
    fields = [node["label"] for node in nodes if node.get("type") == "field"]
    methods = [node["label"] for node in nodes if node.get("type") == "method"]

    evidence: list[str] = []
    if strings:
        evidence.append(f"关联字符串: {', '.join(strings[:8])}")
    if methods:
        evidence.append(f"关联方法: {', '.join(methods[:8])}")
    if fields:
        evidence.append(f"关联字段: {', '.join(fields[:8])}")
    if runtime_methods:
        evidence.append(f"已运行时验证: {', '.join(runtime_methods[:8])}")

    return {
        "focus": focus,
        "summary": "；".join(evidence) if evidence else "当前证据图中没有找到相关节点",
        "runtime_confirmed": runtime_methods,
        "nodes": nodes,
        "edges": edges,
    }
