"""Generate report figures from benchmark JSON or a fresh benchmark run."""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Tuple

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

from benchmarking.runner import SAMPLE_DIR, collect_benchmark_payload, save_payload


def _stage_order() -> List[str]:
    return [
        "parse_auth",
        "parse_network",
        "detection",
        "correlation",
        "triage_enrich",
        "build_context",
        "fallback_report_first_incident",
        "llm_report_first_incident",
    ]


def _load_payload(path: str) -> Dict[str, Any]:
    with open(path) as f:
        return json.load(f)


def _prepare_stages(agg: Dict[str, Dict[str, Any]]) -> Tuple[List[str], List[float], List[float]]:
    order = _stage_order()
    names: List[str] = []
    means_ms: List[float] = []
    stdev_ms: List[float] = []
    for key in order:
        if key not in agg:
            continue
        m = agg[key]["mean_s"] * 1000.0
        if m < 1e-6 and agg[key].get("stdev_s", 0) < 1e-9:
            continue
        names.append(key.replace("_", " "))
        means_ms.append(m)
        stdev_ms.append(agg[key]["stdev_s"] * 1000.0)
    for key in sorted(agg.keys()):
        if key in order or key.endswith("_total"):
            continue
        m = agg[key]["mean_s"] * 1000.0
        names.append(key.replace("_", " "))
        means_ms.append(m)
        stdev_ms.append(agg[key]["stdev_s"] * 1000.0)
    return names, means_ms, stdev_ms


def figure_stage_latency_bar(
    payload: Dict[str, Any],
    out_path: str,
    title: str = "Mean stage latency (±1 stdev)",
) -> None:
    agg = payload["aggregate_stage_seconds"]
    names, means_ms, stdev_ms = _prepare_stages(agg)
    if not names:
        return

    fig, ax = plt.subplots(figsize=(9, max(3.5, 0.35 * len(names))))
    y = range(len(names))
    ax.barh(y, means_ms, xerr=stdev_ms, capsize=3, color="#2ca02c", alpha=0.85, ecolor="#333")
    ax.set_yticks(list(y))
    ax.set_yticklabels(names, fontsize=10)
    ax.set_xlabel("Time (milliseconds)")
    ax.set_title(title)
    ax.grid(axis="x", alpha=0.3)
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)


def figure_pipeline_pie(
    payload: Dict[str, Any],
    out_path: str,
) -> None:
    agg = payload["aggregate_stage_seconds"]
    core_keys = (
        "parse_auth",
        "parse_network",
        "detection",
        "correlation",
        "triage_enrich",
        "build_context",
    )
    labels: List[str] = []
    sizes: List[float] = []
    for k in core_keys:
        if k in agg and agg[k]["mean_s"] > 0:
            labels.append(k.replace("_", " "))
            sizes.append(agg[k]["mean_s"])
    rep = [k for k in agg if "report" in k]
    for k in rep:
        if agg[k]["mean_s"] > 0:
            labels.append(k.replace("_", " "))
            sizes.append(agg[k]["mean_s"])
    if not sizes or sum(sizes) <= 0:
        return
    fig, ax = plt.subplots(figsize=(7, 7))
    ax.pie(sizes, labels=labels, autopct="%1.1f%%", startangle=90, textprops={"fontsize": 9})
    ax.set_title("Share of mean pipeline time by stage")
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)


def figure_workload_counts(
    payload: Dict[str, Any],
    out_path: str,
) -> None:
    ev = payload.get("last_run_event_count", 0)
    det = payload.get("last_run_detection_count", 0)
    inc = payload.get("last_run_incident_count", 0)
    labels = ["Normalized\nevents", "Detection\nresults", "Incidents"]
    vals = [ev, det, inc]
    colors = ["#1f77b4", "#ff7f0e", "#d62728"]
    fig, ax = plt.subplots(figsize=(6, 4))
    bars = ax.bar(labels, vals, color=colors, alpha=0.85)
    ax.set_ylabel("Count (last benchmark run)")
    ax.set_title("Workload snapshot")
    for b, v in zip(bars, vals):
        ax.text(b.get_x() + b.get_width() / 2, b.get_height() + 0.05, str(v), ha="center", va="bottom", fontsize=11)
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)


def figure_throughput(
    payload: Dict[str, Any],
    out_path: str,
) -> None:
    tput = payload.get("throughput_events_per_sec", 0.0)
    wall = payload.get("wall_seconds_all_measured", 0.0)
    runs = payload.get("runs", 1)
    fig, ax = plt.subplots(figsize=(6, 3.5))
    ax.axis("off")
    lines = [
        "Throughput (macro)",
        f"{tput:,.1f} events/s",
        "",
        f"({payload.get('last_run_event_count', 0)} events ÷ {wall:.4f}s wall time for {runs} runs)",
    ]
    ax.text(0.5, 0.5, "\n".join(lines), ha="center", va="center", fontsize=14, family="sans-serif")
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)


def generate_all(
    payload: Dict[str, Any],
    out_dir: str,
    prefix: str = "benchmark",
) -> List[str]:
    os.makedirs(out_dir, exist_ok=True)
    paths = [
        os.path.join(out_dir, f"{prefix}_stage_latency_bar.png"),
        os.path.join(out_dir, f"{prefix}_pipeline_time_share.png"),
        os.path.join(out_dir, f"{prefix}_workload_counts.png"),
        os.path.join(out_dir, f"{prefix}_throughput_summary.png"),
    ]
    figure_stage_latency_bar(payload, paths[0])
    figure_pipeline_pie(payload, paths[1])
    figure_workload_counts(payload, paths[2])
    figure_throughput(payload, paths[3])
    return paths


def main() -> None:
    p = argparse.ArgumentParser(description="Generate benchmark figures for reports.")
    p.add_argument("--json", default="", help="Load benchmark JSON instead of running a new benchmark.")
    p.add_argument("--out-dir", default=os.path.join(os.path.dirname(SAMPLE_DIR), "processed", "figures"))
    p.add_argument("--prefix", default="benchmark", help="Output filename prefix.")
    p.add_argument("--auth", default=os.path.join(SAMPLE_DIR, "auth_linux_sample.csv"))
    p.add_argument("--net", default=os.path.join(SAMPLE_DIR, "network_ids_sample.csv"))
    p.add_argument("--runs", type=int, default=15)
    p.add_argument("--warmup", type=int, default=2)
    p.add_argument(
        "--with-external-intel",
        action="store_true",
        help="Include VT/Abuse during triage (slower; use for end-to-end chart).",
    )
    p.add_argument("--save-json", default="", help="Also write payload JSON next to figures.")
    args = p.parse_args()

    if args.json:
        if not os.path.isfile(args.json):
            print(f"File not found: {args.json}", file=sys.stderr)
            sys.exit(1)
        payload = _load_payload(args.json)
    else:
        if not os.path.isfile(args.auth) or not os.path.isfile(args.net):
            print("Auth or network file missing.", file=sys.stderr)
            sys.exit(1)
        payload = collect_benchmark_payload(
            args.auth,
            args.net,
            runs=args.runs,
            warmup=args.warmup,
            local_only=not args.with_external_intel,
        )

    if args.save_json:
        save_payload(args.save_json, payload)

    paths = generate_all(payload, args.out_dir, prefix=args.prefix)
    print("Wrote figures:")
    for path in paths:
        print(" ", path)


if __name__ == "__main__":
    main()
