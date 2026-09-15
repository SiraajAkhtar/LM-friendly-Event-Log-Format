from __future__ import annotations

import sys
from pathlib import Path
from typing import List

from . import config, preflight
from .runner import cleanup_leftover_artifacts, run_tests
from .tests_definitions import TestCase, get_all_tests


def print_banner() -> None:
    print("=" * 70)
    print(f" {config.APP_NAME}")
    print("=" * 70)


def print_preflight_report(results: List[preflight.CheckResult]) -> None:
    print("\n--- Preflight check ---")
    for r in results:
        print(f"[{r.status.value:4}] {r.name}")
        if r.detail:
            print(f"       {r.detail}")
        if r.status != preflight.Status.PASS and r.fix_hint:
            print(f"       Fix: {r.fix_hint}")
        if r.needs_reboot:
            print("       NOTE: requires a reboot to take effect.")
        if r.affects_tests:
            print(f"       Affects test(s): {', '.join(r.affects_tests)}")
    print()


def offer_auto_fixes(results: List[preflight.CheckResult], output_root: Path) -> List[preflight.CheckResult]:
    fixable = [r for r in results if r.status != preflight.Status.PASS and r.auto_fix]
    if not fixable:
        return results
    print(f"{len(fixable)} issue(s) can be auto-fixed:")
    for r in fixable:
        print(f"  - {r.name}" + (" (needs a reboot to fully take effect)" if r.needs_reboot else ""))
    answer = input("Apply these fixes now? [y/N]: ").strip().lower()
    if not answer.startswith("y"):
        return results
    for r in fixable:
        print(f"  Fixing: {r.name} ...")
        try:
            updated = r.auto_fix()
            print(f"    -> {updated.status.value}")
        except Exception as exc:  # noqa: BLE001
            print(f"    -> failed: {exc}")
    return preflight.run_preflight(output_root)


def select_tests(all_tests: List[TestCase]) -> List[TestCase]:
    print("\nTests:")
    for t in all_tests:
        print(f"  {t.id}  [{t.kind:6}] {t.name}")
    raw = input(
        "\nEnter test IDs to run (comma-separated, ranges like 01-05 allowed), "
        "or press Enter for ALL: "
    ).strip()
    if not raw:
        return all_tests

    wanted: set[str] = set()
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start, end = part.split("-", 1)
            try:
                lo, hi = int(start), int(end)
            except ValueError:
                continue
            wanted.update(f"{n:02d}" for n in range(lo, hi + 1))
        else:
            wanted.add(part.zfill(2))

    selected = [t for t in all_tests if t.id in wanted]
    if not selected:
        print("No matching test IDs  -  running all instead.")
        return all_tests
    return selected


def ask_int(prompt: str, default: int) -> int:
    raw = input(f"{prompt} [{default}]: ").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        print("Not a number, using default.")
        return default


def main() -> int:
    print_banner()
    output_root = config.DEFAULT_OUTPUT_ROOT
    output_root.mkdir(parents=True, exist_ok=True)

    results = preflight.run_preflight(output_root)
    print_preflight_report(results)

    if preflight.has_blocking_failures(results):
        print("Blocking issue(s) found above (FAIL)  -  fix these first, then run this tool again.")
        return 1

    results = offer_auto_fixes(results, output_root)
    print_preflight_report(results)

    cleanup_leftover_artifacts()

    all_tests = get_all_tests()

    while True:
        print("\nMenu:")
        print("  1) Run all tests")
        print("  2) Run selected tests")
        print("  3) Re-run preflight check")
        print("  4) Exit")
        choice = input("Choice: ").strip()

        if choice == "4" or choice.lower() in ("q", "quit", "exit"):
            return 0
        if choice == "3":
            results = preflight.run_preflight(output_root)
            print_preflight_report(results)
            continue
        if choice in ("1", "2"):
            tests = all_tests if choice == "1" else select_tests(all_tests)
            buffer_seconds = ask_int("Buffer between tests (seconds)", config.DEFAULT_BUFFER_SECONDS)
            settle_seconds = ask_int("Settle time after each action, before Stop Recording (seconds)", config.DEFAULT_SETTLE_SECONDS)
            print(
                f"\nAbout to run {len(tests)} test(s). Have EventLogCollector.Gui already "
                f"launched (as Administrator) and ready on its Recording page.\n"
            )
            input("Press Enter to begin... ")
            run_tests(tests, output_root, buffer_seconds=buffer_seconds, settle_seconds=settle_seconds)
            continue
        print("Unrecognised choice.")


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted. Leftover test accounts/exclusions (if any) will be offered for "
              "cleanup the next time this tool is run.")
        sys.exit(130)
