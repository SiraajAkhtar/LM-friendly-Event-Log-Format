import argparse
import gc
import re
import sys
from collections import defaultdict
from pathlib import Path

import torch

import config
from format_adapters import iter_net_entries
from model_loader import build_prompt, generate, load_model

_EXPECTED_SHAPE = re.compile(r"Problem Identified:.*How to resolve:", re.IGNORECASE | re.DOTALL)

OUTPUT_PATH = Path(__file__).resolve().parent / "preflight-output" / "results.txt"


class Tee:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.file = open(path, "w", encoding="utf-8")
        self.stdout = sys.stdout

    def write(self, data):
        self.file.write(data)
        self.stdout.write(data)

    def flush(self):
        self.file.flush()
        self.stdout.flush()


def sample_entries(fmt: str, n: int):
    count = 0
    for scenario_dir in config.SCENARIO_DIRS:
        for entry in iter_net_entries(scenario_dir, fmt):
            yield entry
            count += 1
            if count >= n:
                return


def run_test(test_num: int, model, tokenizer, spec, n: int):
    fmt = config.TESTS[test_num]["format"]
    model_key = config.TESTS[test_num]["model"]
    print(f"\n--- test {test_num}: {model_key} / {fmt} ---")
    flagged = []
    samples = list(sample_entries(fmt, n))
    if not samples:
        print("  (no net entries for this format, nothing to sample)")
        return flagged
    for entry in samples:
        prompt = build_prompt(spec["chat_style"], tokenizer, entry.prompt_text)
        response = generate(model, tokenizer, prompt)
        ok = bool(response) and bool(_EXPECTED_SHAPE.search(response))
        tag = "ok  " if ok else "FLAG"
        print(f"  [{tag}] scenario {entry.scenario}: {response[:200]!r}")
        if not ok:
            flagged.append((entry.scenario, response))
    return flagged


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--n", type=int, default=3, help="samples per test (default 3)")
    parser.add_argument("--test", type=int, choices=list(config.TESTS), default=None,
                         help="check just one test instead of all 8")
    args = parser.parse_args()

    sys.stdout = Tee(OUTPUT_PATH)
    sys.stderr = sys.stdout
    print(f"[preflight] writing results to {OUTPUT_PATH}")

    tests = [args.test] if args.test else list(config.TESTS)
    by_model = defaultdict(list)
    for t in tests:
        by_model[config.TESTS[t]["model"]].append(t)

    all_flags = {}
    for model_key, test_nums in by_model.items():
        spec = config.MODEL_REGISTRY[model_key]
        model, tokenizer = load_model(model_key)
        for t in test_nums:
            flagged = run_test(t, model, tokenizer, spec, args.n)
            if flagged:
                all_flags[t] = flagged
        del model
        torch.cuda.empty_cache()
        gc.collect()

    print("\n=== SUMMARY ===")
    if not all_flags:
        print("All checked tests produced the expected two-sentence shape. "
              "Ready for the real runs.")
    else:
        for t, flagged in all_flags.items():
            print(f"test {t}: {len(flagged)}/{args.n} flagged -- see lines above. "
                  f"Remember: a flag on tests 4-7 may not a bug.")
    print("\n[DONE]")


if __name__ == "__main__":
    main()
