import argparse
import gc
import itertools
import json
import signal
import sys
import time
from pathlib import Path

import torch

import config
from format_adapters import iter_net_entries
from model_loader import build_prompt, generate, load_model

SHOULD_STOP = False


def _request_stop(signum, frame):
    global SHOULD_STOP
    print("\n[STOP, finishing current entry, exiting")
    SHOULD_STOP = True


signal.signal(signal.SIGINT, _request_stop)
signal.signal(signal.SIGTERM, _request_stop)


class Tee:
    def __init__(self, path):
        self.file = open(path, "a", encoding="utf-8")
        self.stdout = sys.stdout

    def write(self, data):
        self.file.write(data)
        self.stdout.write(data)

    def flush(self):
        self.file.flush()
        self.stdout.flush()


def all_entries(fmt: str, max_per_scenario):
    for scenario_dir in config.SCENARIO_DIRS:
        n = 0
        for entry in iter_net_entries(scenario_dir, fmt):
            if max_per_scenario is not None and n >= max_per_scenario:
                break
            yield entry
            n += 1


def count_existing_lines(path: Path) -> int:
    if not path.exists():
        return 0
    with open(path, "r", encoding="utf-8") as f:
        return sum(1 for _ in f)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--test", type=int, choices=list(config.TESTS),
                         help="test number 1-8 -- picks model+format from config.TESTS")
    parser.add_argument("--model", choices=list(config.MODEL_REGISTRY))
    parser.add_argument("--format", choices=list(config.FORMAT_REGISTRY))
    parser.add_argument("--max-entries-per-scenario", type=int, default=None,
                         help="cap per scenario (needed for silketw/winlogbeat -- "
                              "see benchmark_inference.py's suggested value)")
    parser.add_argument("--out-dir", default=None)
    args = parser.parse_args()

    if args.test:
        t = config.TESTS[args.test]
        model_key, fmt = t["model"], t["format"]
        run_name = f"test{args.test}_{model_key}_{fmt}"
    elif args.model and args.format:
        model_key, fmt = args.model, args.format
        run_name = f"{model_key}_{fmt}"
    else:
        parser.error("pass --test N, or both --model and --format")
        return

    out_dir = Path(args.out_dir) if args.out_dir else config.EVAL_OUTPUT_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{run_name}.jsonl"
    log_path = out_dir / f"{run_name}.log"

    sys.stdout = Tee(log_path)
    sys.stderr = sys.stdout

    print(f"\n[START] {time.strftime('%Y-%m-%d %H:%M:%S')} run={run_name}")

    skip_n = count_existing_lines(out_path)
    if skip_n:
        print(f"[RESUME] {skip_n} entries done, skipping ahead")

    spec = config.MODEL_REGISTRY[model_key]
    model, tokenizer = load_model(model_key)

    stream = all_entries(fmt, args.max_entries_per_scenario)
    stream = itertools.islice(stream, skip_n, None)

    done = 0
    noise_note_printed = False
    with open(out_path, "a", encoding="utf-8") as out_f:
        for entry in stream:
            if SHOULD_STOP:
                break

            prompt = build_prompt(spec["chat_style"], tokenizer, entry.prompt_text)

            attempt = 0
            response = None
            duration_s = None
            while attempt <= 2:
                try:
                    t0 = time.perf_counter()
                    response = generate(model, tokenizer, prompt)
                    duration_s = time.perf_counter() - t0
                    break
                except RuntimeError as e:
                    attempt += 1
                    print(f"[ERROR] {entry.scenario}/{entry.source_file}#{entry.row_index}: {e} (retry {attempt})")
                    torch.cuda.empty_cache()
                    gc.collect()
                    time.sleep(1)

            record = {
                "scenario": int(entry.scenario[:2]),
                "log": entry.prompt_text,
                "response": response if response is not None else "[GENERATION FAILED]",
            }
            out_f.write(json.dumps(record) + "\n")
            out_f.flush()

            done += 1
            if done % 25 == 0 or done == 1:
                print(f"[{done}] {entry.scenario} / {entry.source_file} #{entry.row_index} "
                      f"({duration_s:.2f}s)" if duration_s else f"[{done}] {entry.scenario} (failed)")

            if done % 100 == 0:
                torch.cuda.empty_cache()
                gc.collect()

    print(f"\n[DONE] wrote {done} new entries this run -> {out_path}")


if __name__ == "__main__":
    main()
