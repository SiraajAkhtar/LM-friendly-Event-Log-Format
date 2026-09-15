import csv
import glob
import json
import os
import re
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from correctness_calculator import (  # noqa: E402
    parse_problem_resolution,
    model_verdict,
    is_degenerate,
    is_instruction_echo,
    find_fabricated_entities,
    resolution_is_relevant,
    CATEGORIES,
)

EVAL_RESULTS_DIR = os.environ.get(
    "EVAL_RESULTS_DIR",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "slm-eval-results"),
)
OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Results")

TEST_FILES = [
    ("test1", "gemma-base / my_format", "test1_gemma-base_my_format.jsonl"),
    ("test2", "bloomz / my_format", "test2_bloomz_my_format.jsonl"),
    ("test3", "phi3 / my_format", "test3_phi3_my_format.jsonl"),
    ("test4", "gemma-base / original", "test4_gemma-base_original.jsonl"),
    ("test5", "gemma-base / silketw", "test5_gemma-base_silketw.jsonl"),
    ("test6", "gemma-base / winlogbeat", "test6_gemma-base_winlogbeat.jsonl"),
    ("test7", "gemma-base / sysmon", "test7_gemma-base_sysmon.jsonl"),
    ("test8", "gemma-finetuned / my_format", "test8_gemma-finetuned_my_format.jsonl"),
]

# ground truth
SCENARIO_NAMES = {
    1: "Turning off firewall",
    2: "Changing password",
    3: "Changing account permissions",
    4: "Connecting/disconnecting network",
    5: "Launching an application",
    6: "Application crashing",
    7: "Connecting external storage",
    8: "Windows Update configuration change",
    9: "Backup configuration change",
    10: "Time zone change",
    11: "Sharing the screen",
    12: "Application opened in admin mode",
    13: "User took a screenshot",
    14: "Data exported to external location",
    15: "Unauthorised access attempt",
    16: "Added item to Defender allow list",
    17: "Removed item from Defender block list",
    18: "BitLocker drive encryption modification",
    19: "Virus and threat protection modified",
    20: "Windows Defender settings modified",
}


PROBLEM_SCENARIOS = {
    1: ["firewall", "enable", "re-enable", "verify", "security", "restore"],
    2: ["password", "verify", "account", "authorized", "confirm", "credential"],
    3: ["permission", "group", "verify", "access", "authorized", "review"],
    6: CATEGORIES["crash"]["resolution_terms"],
    7: ["scan", "verify", "authorized", "malware", "device", "usb", "storage"],
    8: ["update", "verify", "restore", "policy", "review"],
    9: ["backup", "verify", "restore", "review", "confirm"],
    11: ["verify", "disconnect", "review", "authorized", "display"],
    12: ["verify", "review", "elevated", "privilege", "authorized"],
    13: ["verify", "review", "authorized", "monitor"],
    14: ["verify", "review", "authorized", "data", "monitor"],
    15: CATEGORIES["auth_failure"]["resolution_terms"] + [
        "investigate", "audit", "revoke", "disable", "monitor", "report",
    ],
    16: ["verify", "exclusion", "review", "authorized", "defender"],
    17: ["verify", "exclusion", "review", "defender"],
    18: ["bitlocker", "verify", "encryption", "resume", "review"],
    19: ["defender", "real-time", "enable", "verify", "protection"],
    20: ["defender", "verify", "settings", "review", "restore"],
}

SCENARIO_GROUND_TRUTH = {
    sid: (
        {"verdict": "problem", "resolution_terms": PROBLEM_SCENARIOS[sid]}
        if sid in PROBLEM_SCENARIOS
        else {"verdict": "no_problem", "resolution_terms": None}
    )
    for sid in SCENARIO_NAMES
}

# hallucination
ALARM_TERMS = [
    "malware", "trojan", "ransomware", "compromise", "compromised", "breach",
    "hacked", "hacker", "attacker", "exploit", "backdoor", "spyware",
    "keylogger", "rootkit", "intrusion", "adversary", "threat actor",
    "credential theft", "exfiltrat", "phishing", "brute force", "brute-force",
    "data theft", "stolen", "infiltrat",
]
ALARM_TERMS_RE = re.compile(
    r"\b(" + "|".join(re.escape(t) for t in ALARM_TERMS) + r")\w*", re.IGNORECASE
)
HEDGE_RE = re.compile(
    r"\b(may|might|could|potential\w*|possibl\w*|appears?\s+to|suggest\w*|"
    r"likely|consistent with|warrants?|worth\s+(investigating|reviewing))\b",
    re.IGNORECASE,
)


def find_unsupported_claims(problem_text):
    """Escalatory language (malware/compromise/attacker/...) stated as
    confident fact, not hedged as a possibility - see rationale above."""
    if not problem_text:
        return []
    hits = ALARM_TERMS_RE.findall(problem_text)
    if hits and HEDGE_RE.search(problem_text):
        return []
    return hits


def load_entries(path):
    entries = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            scenario = row.get("scenario")
            output_text = row.get("response", "")
            problem, resolution = parse_problem_resolution(output_text)
            entries.append({
                "id": line_no,
                "scenario": scenario,
                "reference": row.get("log", ""),
                "output_text": output_text,
                "problem": problem,
                "resolution": resolution,
                "parse_ok": problem is not None,
            })
    return entries


def score_one_scenario(entries):
    """Same per-entry scoring logic as correctness_calculator.score_entries,
    but expected verdict/category come from SCENARIO_GROUND_TRUTH instead of
    keyword-matching the reference text."""
    stats = defaultdict(int)
    stats["total"] = len(entries)

    for e in entries:
        gt = SCENARIO_GROUND_TRUTH[e["scenario"]]
        expected_verdict = gt["verdict"]
        resolution_terms = gt["resolution_terms"]

        if not e["parse_ok"]:
            stats["parse_failures"] += 1
            continue

        full_output = (e.get("problem") or "") + " " + (e.get("resolution") or "")

        if is_instruction_echo(full_output):
            stats["instruction_echo"] += 1
            stats["hallucination_graded"] += 1
            stats["hallucination_flagged"] += 1
            continue

        if is_degenerate(full_output):
            stats["malformed"] += 1
            continue

        actual_verdict = model_verdict(e["problem"])

        stats["detection_graded"] += 1
        if actual_verdict == expected_verdict:
            stats["detection_correct"] += 1

        if expected_verdict == "problem" and actual_verdict == "problem":
            relevant = (
                any(term in (e["resolution"] or "").lower() for term in resolution_terms)
                if e["resolution"] else None
            )
            if relevant is not None:
                stats["resolution_graded"] += 1
                if relevant:
                    stats["resolution_correct"] += 1

        fabricated = find_fabricated_entities(e.get("problem"), e["reference"])
        unsupported = find_unsupported_claims(e.get("problem"))
        if e["reference"].strip():
            stats["hallucination_graded"] += 1
            if fabricated or unsupported:
                stats["hallucination_flagged"] += 1
            if fabricated:
                stats["hallucination_fabricated_entity"] += 1
            if unsupported:
                stats["hallucination_unsupported_claim"] += 1

    return stats


def pct(n, d):
    return round(100 * n / d, 1) if d else None


def summarize(stats):
    return {
        "n": stats["total"],
        "detection_accuracy_pct": pct(stats["detection_correct"], stats["detection_graded"]),
        "detection_graded": stats["detection_graded"],
        "resolution_relevance_pct": pct(stats["resolution_correct"], stats["resolution_graded"]),
        "resolution_graded": stats["resolution_graded"],
        "hallucination_rate_pct": pct(stats["hallucination_flagged"], stats["hallucination_graded"]),
        "hallucination_graded": stats["hallucination_graded"],
        "malformed": stats["malformed"],
        "parse_failures": stats["parse_failures"],
        "instruction_echo": stats["instruction_echo"],
    }


def macro_average(values):
    present = [v for v in values if v is not None]
    return round(sum(present) / len(present), 1) if present else None


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    subtest_rows = []
    test_summary_rows = []

    for test_key, test_label, filename in TEST_FILES:
        path = os.path.join(EVAL_RESULTS_DIR, filename)
        if not os.path.exists(path):
            print(f"! Missing file, skipping: {path}")
            continue

        entries = load_entries(path)
        by_scenario = defaultdict(list)
        for e in entries:
            by_scenario[e["scenario"]].append(e)

        det_vals, res_vals, hall_vals = [], [], []

        print("\n" + "=" * 78)
        print(f"{test_key.upper()} - {test_label}  ({len(entries)} total entries)")
        print("=" * 78)
        header = f"{'Scen':>4} {'Name':<40} {'n':>6} {'Detect%':>8} {'Resolve%':>9} {'Halluc%':>8}"
        print(header)
        print("-" * len(header))

        for sid in range(1, 21):
            name = SCENARIO_NAMES[sid]
            sub_entries = by_scenario.get(sid)
            if not sub_entries:
                # never captured an event
                det_vals.append(0.0)
                print(f"{sid:>4} {name:<40} {'0':>6} {'0.0%*':>8} {'n/a':>9} {'n/a':>8}")
                subtest_rows.append({
                    "test": test_key, "test_label": test_label, "scenario": sid,
                    "scenario_name": name, "n": 0, "not_recorded": 1,
                    "detection_accuracy_pct": 0.0, "resolution_relevance_pct": "",
                    "hallucination_rate_pct": "",
                })
                continue

            stats = score_one_scenario(sub_entries)
            s = summarize(stats)
            det_vals.append(s["detection_accuracy_pct"])
            res_vals.append(s["resolution_relevance_pct"])
            hall_vals.append(s["hallucination_rate_pct"])

            def fmt(v):
                return "n/a" if v is None else f"{v}%"

            print(f"{sid:>4} {name:<40} {s['n']:>6} {fmt(s['detection_accuracy_pct']):>8} "
                  f"{fmt(s['resolution_relevance_pct']):>9} {fmt(s['hallucination_rate_pct']):>8}")

            subtest_rows.append({
                "test": test_key, "test_label": test_label, "scenario": sid,
                "scenario_name": name, "n": s["n"], "not_recorded": 0,
                "detection_accuracy_pct": s["detection_accuracy_pct"] if s["detection_accuracy_pct"] is not None else "",
                "resolution_relevance_pct": s["resolution_relevance_pct"] if s["resolution_relevance_pct"] is not None else "",
                "hallucination_rate_pct": s["hallucination_rate_pct"] if s["hallucination_rate_pct"] is not None else "",
            })

        # macro average over 20 scenarios
        avg_det = macro_average(det_vals)
        avg_res = macro_average(res_vals)
        avg_hall = macro_average(hall_vals)
        n_recorded = sum(1 for r in subtest_rows[-20:] if r["not_recorded"] == 0)
        def fmt_avg(v):
            return "n/a" if v is None else f"{v}%"

        print("-" * len(header))
        print(f"Macro avg over all 20 scenarios ({n_recorded} recorded, "
              f"{20 - n_recorded} not recorded -> scored as 0% detection): "
              f"Detection={fmt_avg(avg_det)}  Resolution={fmt_avg(avg_res)}  Hallucination={fmt_avg(avg_hall)}")

        test_summary_rows.append({
            "test": test_key, "test_label": test_label,
            "scenarios_present": n_recorded,
            "total_entries": len(entries),
            "avg_detection_accuracy_pct": avg_det if avg_det is not None else "",
            "avg_resolution_relevance_pct": avg_res if avg_res is not None else "",
            "avg_hallucination_rate_pct": avg_hall if avg_hall is not None else "",
        })

    subtest_csv = os.path.join(OUTPUT_DIR, "results_by_subtest.csv")
    with open(subtest_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(subtest_rows[0].keys()))
        writer.writeheader()
        writer.writerows(subtest_rows)

    summary_csv = os.path.join(OUTPUT_DIR, "results_by_test.csv")
    with open(summary_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(test_summary_rows[0].keys()))
        writer.writeheader()
        writer.writerows(test_summary_rows)

    print("\n" + "=" * 78)
    print("MAIN TEST SUMMARY (1-8), macro-averaged over present scenarios")
    print("=" * 78)
    header = f"{'Test':<6} {'Label':<28} {'Scen':>6} {'Detect%':>8} {'Resolve%':>9} {'Halluc%':>8}"
    print(header)
    print("-" * len(header))
    for row in test_summary_rows:
        print(f"{row['test']:<6} {row['test_label']:<28} {row['scenarios_present']:>3}/20  "
              f"{row['avg_detection_accuracy_pct']!s:>7} "
              f"{row['avg_resolution_relevance_pct']!s:>8} "
              f"{row['avg_hallucination_rate_pct']!s:>8}")

    print(f"\nWrote:\n  {subtest_csv}\n  {summary_csv}")


if __name__ == "__main__":
    main()
