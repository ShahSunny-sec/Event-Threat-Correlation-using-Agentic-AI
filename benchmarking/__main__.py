from __future__ import annotations

import argparse
import json
import os
import sys

from benchmarking.runner import SAMPLE_DIR, collect_benchmark_payload, save_payload


def main() -> None:
    p = argparse.ArgumentParser(
        description="Benchmark SOC pipeline stages (parse → detect → correlate → triage → report).",
    )
    p.add_argument("--auth", default=os.path.join(SAMPLE_DIR, "auth_linux_sample.csv"))
    p.add_argument("--net", default=os.path.join(SAMPLE_DIR, "network_ids_sample.csv"))
    p.add_argument("--runs", type=int, default=5, help="Number of timed iterations (after warmup).")
    p.add_argument("--warmup", type=int, default=1, help="Untimed runs before measurement.")
    p.add_argument("--with-llm", action="store_true", help="Include one LLM report call (needs API key).")
    p.add_argument("--memory", action="store_true", help="Record peak traced Python memory per run.")
    p.add_argument("--json-out", type=str, default="", help="Write full results JSON to this path.")
    p.add_argument(
        "--local-only",
        action="store_true",
        help="Skip VirusTotal/AbuseIPDB calls during triage (fair CPU benchmark).",
    )
    args = p.parse_args()

    if not os.path.isfile(args.auth) or not os.path.isfile(args.net):
        print("Error: auth or network file not found.", file=sys.stderr)
        sys.exit(1)

    payload = collect_benchmark_payload(
        args.auth,
        args.net,
        runs=args.runs,
        warmup=args.warmup,
        with_llm=args.with_llm,
        memory=args.memory,
        local_only=args.local_only,
    )

    agg = payload["aggregate_stage_seconds"]
    timing_only = {k: v for k, v in agg.items() if not k.endswith("_total")}

    print("\n=== SOC Triage Pipeline — Performance Benchmark ===\n")
    print(f"Auth file     : {args.auth}")
    print(f"Network file  : {args.net}")
    print(f"Warmup runs   : {args.warmup}")
    print(f"Measured runs : {args.runs}")
    print(f"Wall clock    : {payload['wall_seconds_all_measured']:.4f}s (all measured runs)")
    print(f"LLM report    : {'yes (first incident)' if args.with_llm else 'no (fallback only)'}")
    print(f"Local triage  : {'yes (no external intel APIs)' if args.local_only else 'no (VT/Abuse if keys in .env)'}")

    print(
        f"\nLast run counts: events={payload['last_run_event_count']}  "
        f"detections={payload['last_run_detection_count']}  "
        f"incidents={payload['last_run_incident_count']}"
    )

    print("\n--- Stage timings (seconds, over measured runs) ---\n")
    print(f"{'Stage':<28} {'mean':>10} {'stdev':>10} {'min':>10} {'max':>10}")
    for name in sorted(timing_only.keys()):
        s = timing_only[name]
        print(
            f"{name:<28} {s['mean_s']:10.6f} {s['stdev_s']:10.6f} "
            f"{s['min_s']:10.6f} {s['max_s']:10.6f}"
        )

    if timing_only:
        pipeline_core = sum(
            timing_only[k]["mean_s"]
            for k in timing_only
            if k
            in (
                "parse_auth",
                "parse_network",
                "detection",
                "correlation",
                "triage_enrich",
                "build_context",
            )
        )
        report_keys = [k for k in timing_only if "report" in k]
        report_mean = sum(timing_only[k]["mean_s"] for k in report_keys)
        print(f"\nCore pipeline (mean): {pipeline_core:.6f}s")
        if report_mean:
            print(f"Report stage (mean): {report_mean:.6f}s")

    if args.memory and payload.get("peak_traced_memory_bytes_max"):
        print(
            f"\nPeak traced memory (Python allocator): "
            f"{payload['peak_traced_memory_bytes_max'] / 1024:.1f} KiB (max over runs)"
        )

    print(
        f"\nThroughput (last-run event count / total wall time): "
        f"{payload['throughput_events_per_sec']:.1f} events/s"
    )

    if args.json_out:
        save_payload(args.json_out, payload)
        print(f"\nWrote JSON: {args.json_out}")

    print("\nTip: For stable CPU timings, close other apps and use --runs 10. "
          "Omit --with-llm to exclude network latency to the LLM API.\n")


if __name__ == "__main__":
    main()
