"""Generate large auth + network CSVs for load testing and benchmarking."""
from __future__ import annotations

import argparse
import csv
import os
import random
from datetime import datetime, timedelta


def _write_auth_row(w, ts, host, user, src_ip, status):
    w.writerow(
        {
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "host": host,
            "user": user,
            "src_ip": src_ip,
            "event_type": "sshd_login",
            "status": status,
        }
    )


def _write_net_row(w, ts, src_ip, dst_ip, src_port, dst_port, protocol, direction, host, alert_name, action):
    w.writerow(
        {
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": str(src_port),
            "dst_port": str(dst_port),
            "protocol": protocol,
            "direction": direction,
            "host": host,
            "alert_name": alert_name,
            "action": action,
        }
    )


def _inject_attack_chain_auth(w, base, host, user, attacker_src):
    for i in range(7):
        ts = base + timedelta(seconds=30 * i)
        _write_auth_row(w, ts, host, user, attacker_src, "failed")
    succ = base + timedelta(minutes=6)
    _write_auth_row(w, succ, host, user, attacker_src, "success")


def _inject_attack_chain_net(w, base, host, victim_src, c2_ip):
    t0 = base + timedelta(minutes=7)
    _write_net_row(w, t0, victim_src, c2_ip, 49152, 443, "tcp", "outbound", host, "", "allowed")
    t1 = t0 + timedelta(seconds=5)
    _write_net_row(
        w,
        t1,
        victim_src,
        c2_ip,
        49152,
        443,
        "tcp",
        "outbound",
        host,
        "ET TROJAN Possible C2 Activity",
        "blocked",
    )
    t2 = t1 + timedelta(minutes=2)
    _write_net_row(w, t2, victim_src, "203.0.113.51", 49200, 8080, "tcp", "outbound", host, "", "allowed")


def generate_auth_csv(path: str, total_rows: int, seed: int, inject_chains: int) -> None:
    rnd = random.Random(seed)
    fieldnames = ["timestamp", "host", "user", "src_ip", "event_type", "status"]
    start = datetime(2024, 3, 15, 8, 0, 0)
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

    benign_hosts = [f"linux-srv-{i:03d}" for i in range(50)]
    benign_users = [f"user{n}@corp.local" for n in range(200)]
    chain_len = 8
    max_chains = max(0, (total_rows - 1) // (chain_len + 1))
    inject_chains = max(0, min(inject_chains, max_chains))
    benign_budget = total_rows - inject_chains * chain_len
    stride = benign_budget // (inject_chains + 1) if inject_chains > 0 else benign_budget
    next_chain_after_benign = stride if inject_chains > 0 else benign_budget + 1

    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()

        t_cursor = start
        benign_written = 0
        chains_done = 0
        rows_out = 0

        while rows_out < total_rows:
            if (
                inject_chains > 0
                and chains_done < inject_chains
                and benign_written >= next_chain_after_benign
            ):
                h = benign_hosts[chains_done % len(benign_hosts)]
                u = f"attacker{chains_done}"
                sip = f"185.{chains_done % 250}.{rnd.randint(1, 200)}.{rnd.randint(1, 200)}"
                _inject_attack_chain_auth(w, t_cursor, h, u, sip)
                t_cursor += timedelta(minutes=50)
                rows_out += chain_len
                chains_done += 1
                next_chain_after_benign = benign_written + stride
                continue

            if benign_written >= benign_budget:
                break

            t_cursor += timedelta(seconds=rnd.randint(1, 20))
            h = rnd.choice(benign_hosts)
            u = rnd.choice(benign_users)
            sip = f"10.{rnd.randint(0, 200)}.{rnd.randint(0, 255)}.{rnd.randint(1, 254)}"
            st = rnd.choices(["success", "failed"], weights=[0.93, 0.07])[0]
            _write_auth_row(w, t_cursor, h, u, sip, st)
            benign_written += 1
            rows_out += 1


def generate_network_csv(path: str, total_rows: int, seed: int, inject_chains: int) -> None:
    rnd = random.Random(seed + 17)
    fieldnames = [
        "timestamp",
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "protocol",
        "direction",
        "host",
        "alert_name",
        "action",
    ]
    start = datetime(2024, 3, 15, 8, 5, 0)
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

    hosts = [f"linux-srv-{i:03d}" for i in range(50)] + [f"WIN-WS-{i:02d}" for i in range(20)]
    public_dst = [("8.8.8.8", 53), ("1.1.1.1", 443), ("151.101.1.140", 443)]

    chain_len = 3
    max_chains = max(0, (total_rows - 1) // (chain_len + 1))
    inject_chains = max(0, min(inject_chains, max_chains))
    benign_budget = total_rows - inject_chains * chain_len
    stride = benign_budget // (inject_chains + 1) if inject_chains > 0 else benign_budget
    next_chain_after_benign = stride if inject_chains > 0 else benign_budget + 1

    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()

        t_cursor = start
        benign_written = 0
        chains_done = 0
        rows_out = 0

        while rows_out < total_rows:
            if (
                inject_chains > 0
                and chains_done < inject_chains
                and benign_written >= next_chain_after_benign
            ):
                victim = f"192.168.{chains_done % 200}.{20 + chains_done % 200}"
                c2 = f"203.0.113.{50 + chains_done % 200}"
                h = hosts[chains_done % len(hosts)]
                _inject_attack_chain_net(w, t_cursor, h, victim, c2)
                t_cursor += timedelta(minutes=45)
                rows_out += chain_len
                chains_done += 1
                next_chain_after_benign = benign_written + stride
                continue

            if benign_written >= benign_budget:
                break

            t_cursor += timedelta(seconds=rnd.randint(2, 25))
            src = f"10.{rnd.randint(0, 50)}.{rnd.randint(0, 255)}.{rnd.randint(1, 250)}"
            dst_ip, dport = rnd.choice(public_dst)
            sport = rnd.randint(40000, 65000)
            h = rnd.choice(hosts)
            direction = rnd.choices(["outbound", "inbound"], weights=[0.86, 0.14])[0]
            alert = ""
            if rnd.random() < 0.02 and direction == "outbound":
                alert = "ET POLICY Suspicious Outbound to Known Bad IP"
            _write_net_row(
                w,
                t_cursor,
                src,
                dst_ip,
                sport,
                dport,
                "tcp",
                direction,
                h,
                alert,
                rnd.choice(["allowed", "blocked"]),
            )
            benign_written += 1
            rows_out += 1


def main() -> None:
    p = argparse.ArgumentParser(
        description="Generate large auth + network CSV files for benchmarking.",
    )
    p.add_argument("--auth-rows", type=int, default=5000, help="Target auth CSV data rows.")
    p.add_argument("--net-rows", type=int, default=8000, help="Target network CSV data rows.")
    p.add_argument(
        "--attack-chains",
        type=int,
        default=5,
        help="Embedded multi-stage attack mini-chains (bounded by row counts).",
    )
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--out-dir", default="", help="Output directory (default: data/benchmark).")
    args = p.parse_args()

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    out_dir = args.out_dir or os.path.join(root, "data", "benchmark")
    os.makedirs(out_dir, exist_ok=True)

    auth_path = os.path.join(out_dir, "auth_volume.csv")
    net_path = os.path.join(out_dir, "network_volume.csv")

    generate_auth_csv(auth_path, args.auth_rows, args.seed, args.attack_chains)
    generate_network_csv(net_path, args.net_rows, args.seed, args.attack_chains)

    def count_data_rows(path: str) -> int:
        with open(path) as fh:
            return max(0, sum(1 for _ in fh) - 1)

    ar = count_data_rows(auth_path)
    nr = count_data_rows(net_path)
    print(f"Wrote {auth_path}  ({ar} data rows)")
    print(f"Wrote {net_path}  ({nr} data rows)")
    print("\nBenchmark:")
    print(
        f"  python3 -m benchmarking --auth {auth_path} --net {net_path} "
        f"--runs 5 --local-only --json-out {os.path.join(out_dir, 'benchmark_large.json')}"
    )
    print(
        f"  python3 -m benchmarking.plot_figures --json {os.path.join(out_dir, 'benchmark_large.json')} "
        f"--prefix benchmark_large --out-dir {os.path.join(out_dir, 'figures')}"
    )


if __name__ == "__main__":
    main()
