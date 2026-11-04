"""Plot measured snapshot/rollback latency and storage from a rollback-bench report.

Reads the JSON written by ``cargo run --release --example rollback_bench`` (see
docs/rollback-benchmark.md); nothing here is synthesised.

    python scripts/plot_rollback_bench.py reports/rollback_bench_2026-11-04.json \
        --out paper/figures/fig3_rollback_latency.png

``load_report`` / ``plot_fig3`` are importable so the paper figure script can
reuse them.
"""

import argparse
import glob
import json
import os


def latest_report(pattern="reports/rollback_bench_*.json"):
    paths = sorted(glob.glob(pattern))
    if not paths:
        raise SystemExit(f"no report matches {pattern}; run the rollback_bench example first")
    return paths[-1]


def load_report(path=None):
    path = path or latest_report()
    with open(path, encoding="utf-8") as fh:
        report = json.load(fh)
    report["_path"] = path
    return report


def plot_fig3(report, out_path, colors=None):
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    colors = colors or ["#0072B2", "#E69F00", "#009E73", "#CC79A7", "#56B4E9"]
    results = report["results"]
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(7.6, 3.8), dpi=300)

    for i, r in enumerate(results):
        c = colors[i % len(colors)]
        turns = list(range(len(r["per_turn_snapshot_ms_median"])))
        label = f"{r['files']:,} files"
        ax1.plot(turns, r["per_turn_snapshot_ms_median"], "o-", color=c, markersize=3,
                 linewidth=1.4, label=f"snapshot, {label}")
        rb = r["rollback_latency_ms"]
        ax1.axhline(rb["median"], color=c, linestyle="--", linewidth=1.0,
                    label=f"rollback median, {label}")
        cumulative = []
        total = 0.0
        for b in r["per_turn_snapshot_bytes_median"]:
            total += b
            cumulative.append(total / 1e6)
        ax2.plot(turns, cumulative, "o-", color=c, markersize=3, linewidth=1.4, label=label)

    ax1.axhline(50, color="#555555", linestyle=":", linewidth=1.0, label="50 ms")
    ax1.set_yscale("log")
    ax1.set_xlabel("Edit turn (0 = baseline)")
    ax1.set_ylabel("Latency (ms, median of runs)")
    ax1.set_title("a | Snapshot and rollback latency (measured)", fontsize=9)
    ax1.legend(fontsize=5.5, loc="best")

    ax2.set_xlabel("Edit turn (0 = baseline)")
    ax2.set_ylabel("Cumulative snapshot store (MB)")
    ax2.set_title("b | Snapshot storage growth (measured)", fontsize=9)
    ax2.legend(fontsize=6.5, loc="upper left")

    rev = (report.get("git_rev") or "unknown")[:8]
    fig.suptitle(f"Figure 3 | Ethos snapshot/rewind cost (rollback_bench @ {rev})",
                 fontsize=10, fontweight="bold", y=1.02)
    fig.tight_layout()
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    fig.savefig(out_path, dpi=300, bbox_inches="tight")
    plt.close(fig)
    return out_path


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("report", nargs="?", help="report JSON (default: newest reports/rollback_bench_*.json)")
    ap.add_argument("--out", default="paper/figures/fig3_rollback_latency.png")
    args = ap.parse_args()
    report = load_report(args.report)
    print(f"[+] {plot_fig3(report, args.out)} from {report['_path']}")


if __name__ == "__main__":
    main()
