"""A/B 分叉条件运行时值提取与比较测试。"""
from __future__ import annotations

from reconbridge_mcp import condition_probe


def _field_probe():
    return {
        "kind": "field",
        "class": "com.example.PayManager",
        "method": "checkVip",
        "field": "premiumStatus",
        "condition_rank": 1,
        "condition_line": 101,
        "condition": "premiumStatus",
    }


def _capture(name, value):
    probe = _field_probe()
    summary = condition_probe.summarize_values(
        [
            {
                "phase": "before",
                "ts": 100,
                "tid": 7,
                "fields": [
                    {
                        "target": "this",
                        "name": "premiumStatus",
                        "value": value,
                    }
                ],
            },
            {
                "phase": "after",
                "ts": 120,
                "tid": 7,
                "fields": [
                    {
                        "target": "this",
                        "name": "premiumStatus",
                        "value": value,
                    }
                ],
            },
        ],
        probe,
    )
    return {
        "scenario": name,
        "probe_fingerprint": condition_probe.probe_fingerprint(probe),
        "probe": probe,
        "summary": summary,
    }


def test_field_probe_extracts_boolean_value():
    capture = _capture("非会员", "false")

    assert capture["summary"]["sample_count"] == 2
    assert capture["summary"]["stable"] is True
    assert capture["summary"]["stable_value"]["type"] == "boolean"
    assert capture["summary"]["stable_value"]["value"] is False


def test_condition_method_probe_extracts_return_value():
    probe = {
        "kind": "condition_method",
        "class": "com.example.PayManager",
        "method": "isPremiumUser",
        "condition_rank": 1,
        "condition_line": 50,
        "condition": "isPremiumUser()",
    }
    summary = condition_probe.summarize_values(
        [
            {"phase": "after", "ret": True, "ts": 100, "tid": 7},
            {"phase": "after", "ret": "true", "ts": 110, "tid": 7},
        ],
        probe,
    )

    assert summary["stable"] is True
    assert summary["stable_value"]["value"] is True
    assert summary["sample_count"] == 2


def test_boolean_probe_confirms_branch_orientation():
    capture_a = _capture("非会员", "false")
    capture_b = _capture("会员", "true")

    result = condition_probe.compare_captures(
        capture_a,
        capture_b,
        branch_orientation="a_false_b_true",
    )

    assert result["ok"] is True
    assert result["status"] == "branch_orientation_confirmed"
    assert result["orientation_match"] is True
    assert result["evidence_level"] == "strong_correlated"
    assert result["a"]["value"]["value"] is False
    assert result["b"]["value"]["value"] is True


def test_condition_method_return_is_direct_branch_evidence():
    probe = {
        "kind": "condition_method",
        "class": "com.example.PayManager",
        "method": "isPremiumUser",
        "condition_rank": 1,
        "condition_line": 50,
        "condition": "isPremiumUser()",
    }

    def capture(name, value):
        return {
            "scenario": name,
            "probe_fingerprint": condition_probe.probe_fingerprint(probe),
            "probe": probe,
            "summary": condition_probe.summarize_values(
                [
                    {
                        "phase": "after",
                        "ret": value,
                        "ts": 100,
                        "tid": 7,
                    }
                ],
                probe,
            ),
        }

    result = condition_probe.compare_captures(
        capture("A", False),
        capture("B", True),
        branch_orientation="a_false_b_true",
    )

    assert result["status"] == "branch_orientation_confirmed"
    assert result["evidence_level"] == "direct"
    assert "条件方法返回值" in result["explanation"]


def test_same_stable_value_does_not_explain_divergence():
    capture_a = _capture("A", "true")
    capture_b = _capture("B", True)

    result = condition_probe.compare_captures(capture_a, capture_b)

    assert result["status"] == "same_value"
    assert result["evidence_level"] == "inconclusive"


def test_unstable_values_are_marked_inconclusive():
    probe = _field_probe()
    summary = condition_probe.summarize_values(
        [
            {
                "fields": [{"name": "premiumStatus", "value": "false"}],
            },
            {
                "fields": [{"name": "premiumStatus", "value": "true"}],
            },
        ],
        probe,
    )
    capture_a = {
        "scenario": "A",
        "probe_fingerprint": condition_probe.probe_fingerprint(probe),
        "summary": summary,
    }
    capture_b = _capture("B", "true")

    result = condition_probe.compare_captures(
        capture_a,
        capture_b,
        branch_orientation="a_false_b_true",
    )

    assert result["status"] == "unstable"
    assert result["evidence_level"] == "inconclusive"


def test_different_probe_fingerprint_is_rejected():
    capture_a = _capture("A", "false")
    capture_b = _capture("B", "true")
    capture_b["probe_fingerprint"] = "different"

    result = condition_probe.compare_captures(capture_a, capture_b)

    assert result["ok"] is False
    assert result["status"] == "probe_mismatch"
