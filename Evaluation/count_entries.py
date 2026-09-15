import argparse
import json
import statistics
import sys
from pathlib import Path

import config
from format_adapters import iter_entries


def count_scenario_format(scenario_dir: Path, fmt: str) -> dict:
    total = 0
    noise = 0
    lengths = []
    for entry in iter_entries(scenario_dir, fmt):
        total += 1
        if entry.is_noise:
            noise += 1
        else:
            lengths.append(len(entry.prompt_text))
    net = total - noise
    return {
        "total": total,
        "noise_excluded": noise,
        "net": net,
        "mean_chars": round(statistics.mean(lengths), 1) if lengths else 0,
        "max_chars": max(lengths) if lengths else 0,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default=str(Path(__file__).parent / "entry_counts.json"))
    args = parser.parse_args()

    if not config.SCENARIO_DIRS:
        print(f"No scenario folders found under {config.RESULTS_DIR}", file=sys.stderr)
        sys.exit(1)

    results = {}
    totals = {fmt: {"total": 0, "noise_excluded": 0, "net": 0} for fmt in config.FORMAT_REGISTRY}

    for scenario_dir in config.SCENARIO_DIRS:
        results[scenario_dir.name] = {}
        for fmt in config.FORMAT_REGISTRY:
            stats = count_scenario_format(scenario_dir, fmt)
            results[scenario_dir.name][fmt] = stats
            totals[fmt]["total"] += stats["total"]
            totals[fmt]["noise_excluded"] += stats["noise_excluded"]
            totals[fmt]["net"] += stats["net"]
        print(f"  {scenario_dir.name} done", file=sys.stderr)

    output = {"per_scenario": results, "totals": totals}
    Path(args.out).write_text(json.dumps(output, indent=2), encoding="utf-8")

    col_w = 12
    header = "format".ljust(28) + "".join(c.ljust(col_w) for c in ["total", "noise_excl", "net"])
    print("\n" + header)
    print("-" * len(header))
    for fmt, t in totals.items():
        print(fmt.ljust(28) + "".join(str(t[k]).ljust(col_w) for k in ["total", "noise_excluded", "net"]))
    print(f"\nWrote {args.out}")


if __name__ == "__main__":
    main()
