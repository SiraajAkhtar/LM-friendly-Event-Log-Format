import argparse
import re
from collections import defaultdict

import config
from format_adapters import iter_net_entries

_PERCENT_ENCODING = re.compile(r"(?<!%)%[0-9A-Fa-f]{2}")

_WATCHLIST = [
    re.compile(r"Testing Script", re.IGNORECASE),
    re.compile(r"EventLogCollector", re.IGNORECASE),
    re.compile(r"_scratch", re.IGNORECASE),
    re.compile(r"ELCTest_", re.IGNORECASE),
    re.compile(r"\.ps1\b", re.IGNORECASE),
    re.compile(r"SilkETW", re.IGNORECASE),
    re.compile(r"Winlogbeat", re.IGNORECASE),
    re.compile(r"wevtutil", re.IGNORECASE),
]


_SELF_REFERENCE = {"silketw": "SilkETW", "winlogbeat": "Winlogbeat"}


def check_format(fmt: str, max_samples: int):
    flagged = defaultdict(list)
    total = 0
    skip_pattern = _SELF_REFERENCE.get(fmt)
    for scenario_dir in config.SCENARIO_DIRS:
        for entry in iter_net_entries(scenario_dir, fmt):
            total += 1
            text = entry.prompt_text

            if not text or not text.strip():
                flagged["empty"].append(entry)
                continue

            if _PERCENT_ENCODING.search(text):
                flagged["percent_encoded"].append(entry)

            for pattern in _WATCHLIST:
                if skip_pattern and pattern.pattern == skip_pattern:
                    continue
                if pattern.search(text):
                    flagged[f"watchlist:{pattern.pattern}"].append(entry)

    print(f"\n=== {fmt} ({total} net entries) ===")
    if not flagged:
        print("  clean -- no flags")
        return

    for reason, entries in sorted(flagged.items(), key=lambda kv: -len(kv[1])):
        print(f"  [{reason}] {len(entries)} entries")
        for e in entries[:max_samples]:
            preview = e.prompt_text[:160].replace("\n", " ")
            print(f"      {e.scenario} #{e.row_index}: {preview}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--format", choices=list(config.FORMAT_REGISTRY), default=None,
                         help="check just one format (default: all 5)")
    parser.add_argument("--samples", type=int, default=3,
                         help="how many example rows to print per flag")
    args = parser.parse_args()

    formats = [args.format] if args.format else list(config.FORMAT_REGISTRY)
    for fmt in formats:
        check_format(fmt, args.samples)


if __name__ == "__main__":
    main()
