from __future__ import annotations

import statistics
import time
import tracemalloc
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List, Optional


@dataclass
class StageTiming:
    name: str
    seconds: float
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RunResult:
    stages: List[StageTiming] = field(default_factory=list)
    peak_memory_bytes: Optional[int] = None
    event_count: int = 0
    detection_count: int = 0
    incident_count: int = 0


def total_seconds(stages: List[StageTiming]) -> float:
    return sum(s.seconds for s in stages)


def aggregate_stage_times(runs: List[RunResult]) -> Dict[str, Dict[str, float]]:
    by_name: Dict[str, List[float]] = {}
    for run in runs:
        for st in run.stages:
            by_name.setdefault(st.name, []).append(st.seconds)
    out: Dict[str, Dict[str, float]] = {}
    for name, vals in by_name.items():
        out[name] = {
            "mean_s": statistics.mean(vals),
            "stdev_s": statistics.stdev(vals) if len(vals) > 1 else 0.0,
            "min_s": min(vals),
            "max_s": max(vals),
            "runs": float(len(vals)),
        }
    return out


@contextmanager
def timed_stage(
    name: str,
    stages: List[StageTiming],
    extra: Optional[Dict[str, Any]] = None,
) -> Iterator[None]:
    t0 = time.perf_counter()
    try:
        yield
    finally:
        stages.append(
            StageTiming(name=name, seconds=time.perf_counter() - t0, extra=extra or {})
        )


@contextmanager
def memory_trace() -> Iterator[None]:
    tracemalloc.start()
    try:
        yield
    finally:
        tracemalloc.stop()


def peak_traced_memory_bytes() -> int:
    if not tracemalloc.is_tracing():
        return 0
    current, peak = tracemalloc.get_traced_memory()
    return peak
