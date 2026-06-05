import pytest

from benchmarking.performance import RunResult, StageTiming, aggregate_stage_times, total_seconds


def test_aggregate_stage_times_mean():
    r1 = RunResult(
        stages=[
            StageTiming("parse_auth", 0.01),
            StageTiming("detection", 0.02),
        ]
    )
    r2 = RunResult(
        stages=[
            StageTiming("parse_auth", 0.03),
            StageTiming("detection", 0.04),
        ]
    )
    agg = aggregate_stage_times([r1, r2])
    assert agg["parse_auth"]["mean_s"] == 0.02
    assert agg["detection"]["mean_s"] == 0.03


def test_total_seconds():
    stages = [StageTiming("a", 0.1), StageTiming("b", 0.2)]
    assert total_seconds(stages) == pytest.approx(0.3)
