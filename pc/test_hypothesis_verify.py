"""Root Cause 最小假设实验测试。"""
from __future__ import annotations

from reconbridge_mcp import hypothesis_verify


def _candidate():
    return {
        "rank": 1,
        "candidate_key": "method:com.example.Repo#isVipEnabled(Z)Z",
        "candidate_type": "method",
        "class": "com.example.Repo",
        "method": "isVipEnabled",
        "descriptor": "(ZLjava/lang/String;)Z",
        "label": "com.example.Repo.isVipEnabled",
        "score": 80,
    }


def _context():
    return {
        "source": {
            "available": True,
            "text": """  10 | boolean isVipEnabled(boolean force, String userId) {
  11 |     return force || premiumStatus || repository.isVip(userId);
  12 | }
""",
        },
        "relations": {
            "class_fields": [
                {
                    "class": "Lcom/example/Repo;",
                    "field": "premiumStatus",
                    "type": "Z",
                },
                {
                    "class": "Lcom/example/Repo;",
                    "field": "unusedField",
                    "type": "Ljava/lang/Object;",
                },
            ]
        },
    }


def test_descriptor_parser_generates_precise_java_params():
    parsed = hypothesis_verify.parse_method_descriptor(
        "(ZLjava/lang/String;I)Ljava/lang/Boolean;"
    )

    assert parsed["ok"] is True
    assert parsed["precise_params"] is True
    assert [item["java_name"] for item in parsed["params"]] == [
        "boolean",
        "java.lang.String",
        "int",
    ]
    assert parsed["return"]["java_name"] == "java.lang.Boolean"


def test_array_descriptor_degrades_exact_overload_precision():
    parsed = hypothesis_verify.parse_method_descriptor(
        "([Ljava/lang/String;)Z"
    )

    assert parsed["ok"] is True
    assert parsed["params"][0]["java_name"] == "java.lang.String[]"
    assert parsed["precise_params"] is False


def test_plan_captures_only_referenced_fields_and_needed_args():
    plan = hypothesis_verify.plan_experiment(
        _candidate(),
        _context(),
    )

    assert plan["ok"] is True
    assert plan["overload_precision"] == "exact"
    assert plan["params"] == ["boolean", "java.lang.String"]
    assert [item["index"] for item in plan["capture_args"]] == [0, 1]
    assert [item["name"] for item in plan["capture_fields"]] == [
        "premiumStatus"
    ]
    assert plan["capture_return"] is True
    assert plan["return_render"] == "tostring"
    assert plan["input_coverage"]["complete"] is True


def _event(phase, force, user_id, field, ret=None, tid=7, ts=100):
    row = {
        "phase": phase,
        "tid": tid,
        "ts": ts,
        "args": [
            {"index": 0, "value": force},
            {"index": 1, "value": user_id},
        ],
        "fields": [
            {"name": "premiumStatus", "value": field},
        ],
    }
    if phase == "after":
        row["ret"] = ret
    return row


def _capture(name, force, user_id, field, ret):
    plan = hypothesis_verify.plan_experiment(
        _candidate(),
        _context(),
    )
    events = [
        _event("before", force, user_id, field, tid=7, ts=100),
        _event("after", force, user_id, field, ret=ret, tid=7, ts=120),
    ]
    return {
        "scenario": name,
        "hypothesis_fingerprint": plan["hypothesis_fingerprint"],
        "candidate_key": plan["candidate_key"],
        "analysis": hypothesis_verify.analyze_capture(events, plan),
    }


def test_same_inputs_different_output_supports_internal_generation():
    left = _capture("A", False, "u1", False, False)
    right = _capture("B", False, "u1", False, True)

    result = hypothesis_verify.compare_captures(left, right)

    assert result["status"] == "internal_generation_supported"
    assert result["score_adjustment"] == 30
    assert result["input_coverage_complete"] is True
    assert result["differing_inputs"] == []
    assert result["differing_outputs"][0]["name"] == "return"


def test_different_input_demotes_candidate_to_upstream():
    left = _capture("A", False, "u1", False, False)
    right = _capture("B", True, "u1", False, True)

    result = hypothesis_verify.compare_captures(left, right)

    assert result["status"] == "upstream_input_difference"
    assert result["score_adjustment"] == -30
    assert result["differing_inputs"][0]["name"] == "args[0]"


def test_same_output_is_not_reproduced():
    left = _capture("A", False, "u1", False, True)
    right = _capture("B", False, "u1", False, True)

    result = hypothesis_verify.compare_captures(left, right)

    assert result["status"] == "not_reproduced"
    assert result["score_adjustment"] == -25


def test_partial_input_coverage_never_claims_strong_internal_generation():
    candidate = _candidate()
    candidate["descriptor"] = "(ZZZZZZZZZ)Z"
    plan = hypothesis_verify.plan_experiment(
        candidate,
        _context(),
        max_args=2,
    )

    def capture(name, ret):
        return {
            "scenario": name,
            "hypothesis_fingerprint": plan["hypothesis_fingerprint"],
            "candidate_key": plan["candidate_key"],
            "analysis": {
                "input_coverage": plan["input_coverage"],
                "args": {
                    "0": {
                        "stable": True,
                        "stable_value": {
                            "type": "boolean",
                            "value": False,
                            "canonical": "false",
                        },
                    }
                },
                "fields_before": {},
                "fields_after": {},
                "return": {
                    "stable": True,
                    "stable_value": {
                        "type": "boolean",
                        "value": ret,
                        "canonical": "true" if ret else "false",
                    },
                },
            },
        }

    result = hypothesis_verify.compare_captures(
        capture("A", False),
        capture("B", True),
    )

    assert plan["input_coverage"]["complete"] is False
    assert result["status"] == "internal_generation_partial"
    assert result["score_adjustment"] == 15


def test_missing_runtime_field_prevents_strong_internal_confirmation():
    plan = hypothesis_verify.plan_experiment(
        _candidate(),
        _context(),
    )

    def capture(name, ret):
        return {
            "scenario": name,
            "hypothesis_fingerprint": plan["hypothesis_fingerprint"],
            "candidate_key": plan["candidate_key"],
            "analysis": {
                "input_coverage": plan["input_coverage"],
                "args": {
                    "0": {
                        "stable": True,
                        "stable_value": {
                            "type": "boolean",
                            "value": False,
                            "canonical": "false",
                        },
                    },
                    "1": {
                        "stable": True,
                        "stable_value": {
                            "type": "string",
                            "value": "u1",
                            "canonical": "u1",
                        },
                    },
                },
                # premiumStatus 在计划里，但本轮运行时没有实际读到。
                "fields_before": {
                    "premiumStatus": {
                        "stable": False,
                        "sample_count": 0,
                        "stable_value": None,
                    }
                },
                "fields_after": {},
                "return": {
                    "stable": True,
                    "stable_value": {
                        "type": "boolean",
                        "value": ret,
                        "canonical": "true" if ret else "false",
                    },
                },
            },
        }

    result = hypothesis_verify.compare_captures(
        capture("A", False),
        capture("B", True),
    )

    assert result["planned_input_count"] == 3
    assert result["comparable_input_count"] == 2
    assert result["observed_input_complete"] is False
    assert result["input_coverage_complete"] is False
    assert result["status"] == "internal_generation_partial"


def test_capture_uses_primary_thread_not_background_noise():
    plan = hypothesis_verify.plan_experiment(
        _candidate(),
        _context(),
    )
    events = [
        _event("before", False, "u1", False, tid=7, ts=100),
        _event("after", False, "u1", False, ret=True, tid=7, ts=120),
        _event("before", True, "noise", True, tid=99, ts=130),
    ]

    result = hypothesis_verify.analyze_capture(events, plan)

    assert result["primary_tid"] == 7
    assert result["args"]["0"]["stable_value"]["value"] is False
    assert result["return"]["stable_value"]["value"] is True
