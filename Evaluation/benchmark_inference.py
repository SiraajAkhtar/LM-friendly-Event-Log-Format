import argparse
import json
import statistics
import time
from pathlib import Path

import config
from format_adapters import iter_net_entries
from model_loader import build_prompt, generate, load_model


def sample_entries(fmt: str, n: int):
    picked = []
    per_scenario = max(1, n // max(1, len(config.SCENARIO_DIRS)))
    for scenario_dir in config.SCENARIO_DIRS:
        count = 0
        for entry in iter_net_entries(scenario_dir, fmt):
            picked.append(entry)
            count += 1
            if count >= per_scenario:
                break
        if len(picked) >= n:
            break
    return picked[:n]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", required=True, choices=list(config.MODEL_REGISTRY))
    parser.add_argument("--format", required=True, choices=list(config.FORMAT_REGISTRY))
    parser.add_argument("--n", type=int, default=20, help="number of timed entries")
    parser.add_argument("--budget-hours", type=float, default=20.0,
                         help="wall-clock budget for this format's test slot, "
                              "used to compute a suggested sample cap")
    parser.add_argument("--counts", default=str(Path(__file__).parent / "entry_counts.json"))
    args = parser.parse_args()

    entries = sample_entries(args.format, args.n)
    if not entries:
        print(f"No entries found for format={args.format} -- check RESULTS_DIR / noise filter.")
        return

    spec = config.MODEL_REGISTRY[args.model]
    model, tokenizer = load_model(args.model)

    
    warm_prompt = build_prompt(spec["chat_style"], tokenizer, entries[0].prompt_text)
    generate(model, tokenizer, warm_prompt)

    durations = []
    for entry in entries:
        prompt = build_prompt(spec["chat_style"], tokenizer, entry.prompt_text)
        t0 = time.perf_counter()
        generate(model, tokenizer, prompt)
        durations.append(time.perf_counter() - t0)
        print(f"  {entry.scenario} / {entry.source_file} #{entry.row_index}: {durations[-1]:.2f}s")

    mean_s = statistics.mean(durations)
    median_s = statistics.median(durations)
    p95_s = sorted(durations)[int(len(durations) * 0.95) - 1] if len(durations) > 1 else durations[0]

    print(f"\n--- {args.model} / {args.format} over {len(durations)} timed entries ---")
    print(f"mean={mean_s:.2f}s  median={median_s:.2f}s  p95={p95_s:.2f}s")

    counts_path = Path(args.counts)
    if counts_path.exists():
        counts = json.loads(counts_path.read_text(encoding="utf-8"))
        net_total = counts["totals"].get(args.format, {}).get("net")
        if net_total:
            projected_hours = net_total * mean_s / 3600
            print(f"Net entries for {args.format} across all 20 scenarios: {net_total}")
            print(f"Projected exhaustive runtime at mean rate: {projected_hours:.1f} hours")
            if projected_hours > args.budget_hours:
                budget_entries = int(args.budget_hours * 3600 / mean_s)
                per_scenario_cap = max(1, budget_entries // max(1, len(config.SCENARIO_DIRS)))
                print(
                    f"Exceeds --budget-hours ({args.budget_hours}h). Suggested cap: "
                    f"--max-entries-per-scenario {per_scenario_cap} "
                    f"(~{per_scenario_cap * len(config.SCENARIO_DIRS)} entries total, "
                    f"~{per_scenario_cap * len(config.SCENARIO_DIRS) * mean_s / 3600:.1f}h)"
                )
            else:
                print("Fits within --budget-hours exhaustively -- no sampling needed.")
    else:
        print(f"(no {counts_path} found -- run count_entries.py first for a runtime projection)")


if __name__ == "__main__":
    main()
