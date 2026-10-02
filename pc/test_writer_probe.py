"""字段 writer 运行时变化分析测试。"""
from __future__ import annotations

from reconbridge_mcp import writer_probe


def _event(phase, value, ts, tid=7, seq=0):
    return {
        "phase": phase,
        "ts": ts,
        "tid": tid,
        "seq": seq,
        "fields": [{"name": "premiumStatus", "value": value}],
    }


def test_writer_probe_detects_false_to_true_change():
    result = writer_probe.analyze_writer_events(
        [
            _event("before", "false", 100, seq=1),
            _event("after", "true", 120, seq=2),
        ],
        "premiumStatus",
    )

    assert result["paired_calls"] == 1
    assert result["changed_calls"] == 1
    assert result["changed"] is True
    assert result["distinct_changes"][0]["before"]["value"] is False
    assert result["distinct_changes"][0]["after"]["value"] is True


def test_writer_probe_pairs_calls_per_thread():
    result = writer_probe.analyze_writer_events(
        [
            _event("before", "false", 100, tid=10, seq=1),
            _event("before", "true", 101, tid=20, seq=2),
            _event("after", "true", 110, tid=10, seq=3),
            _event("after", "true", 111, tid=20, seq=4),
        ],
        "premiumStatus",
    )

    assert result["paired_calls"] == 2
    assert result["changed_calls"] == 1
    changed = next(item for item in result["transitions"] if item["changed"])
    assert changed["tid"] == 10


def test_writer_probe_no_change_is_reported():
    result = writer_probe.analyze_writer_events(
        [
            _event("before", "true", 100, seq=1),
            _event("after", "true", 120, seq=2),
        ],
        "premiumStatus",
    )

    assert result["changed"] is False
    assert result["changed_calls"] == 0
