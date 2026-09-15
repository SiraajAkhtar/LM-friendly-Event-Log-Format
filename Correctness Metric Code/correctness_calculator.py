import json
import re
import sys
import zipfile
from collections import Counter

CATEGORIES = {
    "crash": {
        "indicators": [
            r"faulting application", r"appcrash", r"exception code",
            r"stopped interacting with windows", r"application hang",
            r"access violation", r"stopped working", r"fault bucket",
        ],
        "resolution_terms": [
            "update", "reinstall", "sfc", "driver", "safe mode", "repair",
            "crash", "patch", "dism",
        ],
    },
    "service_failure": {
        "indicators": [
            r"service terminated unexpectedly", r"service was stopped\b",
            r"service stopped unexpectedly", r"service entered the stopped state",
        ],
        "resolution_terms": [
            "restart", "service", "net start", "services.msc",
        ],
    },
    "performance": {
        # threshold breaches only
        "indicators": [
            r"exceeded threshold", r"fallen below threshold", r"below threshold",
            r"bottleneck", r"abnormally high", r"critically low",
        ],
        "resolution_terms": [
            "monitor", "task manager", "resource", "close", "ram", "upgrade",
            "optimi",
        ],
    },
    "auth_failure": {
        "indicators": [
            r"failed to log on", r"bad password", r"unknown user name",
            r"account failed to log on",
        ],
        "resolution_terms": [
            "password", "account", "lockout", "credential", "verify",
        ],
    },
    "permission_dcom": {
        "indicators": [
            r"does not grant", r"local activation permission", r"\bdcom\b",
        ],
        "resolution_terms": [
            "component services", "dcomcnfg", "permission", "security tab",
        ],
    },
    "power_failure": {
        "indicators": [
            r"rebooted without cleanly shutting down", r"unexpected shutdown",
            r"lost power", r"previous system shutdown.*unexpected",
        ],
        "resolution_terms": [
            "power supply", "memory diagnostic", "driver", "bios", "temperature",
        ],
    },
    "network": {
        "indicators": [
            r"timed out", r"\bdns\b", r"cannot locate the server",
            r"network is not started",
        ],
        "resolution_terms": [
            "dns", "network", "connectivity", "firewall", "adapter",
        ],
    },
    "disk_driver": {
        "indicators": [
            r"blocked from loading", r"device is not ready",
            r"disk queue length", r"raidport",
        ],
        "resolution_terms": [
            "driver", "device manager", "chkdsk", "disk",
        ],
    },
    "file_error": {
        "indicators": [
            r"cannot find the file specified", r"file not found",
            r"access is denied",
        ],
        "resolution_terms": [
            "file", "path", "permission", "reinstall",
        ],
    },
    "generic_error": {
        "indicators": [
            r"error[\s\-]?-?\d+.*occurred", r"failed .*activation attempt",
            r"duplicate definition of", r"unavailable to handle a notification",
            r"could not be (loaded|started|found|completed)",
        ],
        "resolution_terms": [
            "check", "verify", "review", "restart", "update",
        ],
    },
}

BENIGN_INDICATORS = [
    r"successfully logged on", r"entered the running state", r"\(planned\)",
    r"cleared the .*log", r"service was started\b", r"no obvious issues found",
    r"migration succeeded", r"successfully scheduled",
    r"skipping creation of restore point",
]

NO_PROBLEM_PHRASES = [
    "non identified", "non-identified", "not identified", "none identified",
    "no issue identified", "no issues found", "no problem", "no problems found",
    "no problems detected", "no computational issue",
]

NO_ACTION_ONLY_PHRASES = [
    "no following steps required", "no action needed", "no action required",
]


ENTITY_CHECKS = [
    ("filename", re.compile(r"\b[\w\-]+\.(?:exe|dll|sys|msc)\b", re.IGNORECASE)),
    ("hex", re.compile(r"0x[0-9a-fA-F]{4,8}\b")),
]

PROBLEM_RESOLVE_RE = re.compile(
    r"Problem\s*Identified:\s*(.*?),?\s*How\s*to\s*[Rr]esolve:\s*(.*)",
    re.IGNORECASE | re.DOTALL,
)

LOG_LINE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}.*$", re.MULTILINE)

GROUP_HEADER_RE = re.compile(
    r"^-{2,}\s*(Correlated\s+)?Group\s+(\d+)[^\n]*-{2,}\s*$", re.IGNORECASE | re.MULTILINE
)

DEGENERATE_RE = re.compile(r"\b(\w+)\b(?:\s+\1\b){7,}", re.IGNORECASE)

# detect no responses/default responses
TEMPLATE_ECHO_RE = re.compile(
    r"<[^<>]{0,80}(?:description of issue|instructions to fix|no issues found)[^<>]{0,40}>",
    re.IGNORECASE,
)
TEMPLATE_ECHO_PHRASES = [
    "short description of issue", "step-by-step instructions to fix the issue",
]


def is_instruction_echo(text):
    if not text:
        return False
    if TEMPLATE_ECHO_RE.search(text):
        return True
    lowered = text.lower()
    return any(phrase in lowered for phrase in TEMPLATE_ECHO_PHRASES)


REFUSAL_RE = re.compile(r"sorry.{0,20}(can ?not|cannot).{0,40}answer", re.IGNORECASE)
LOG_STRUCTURE_RE = re.compile(r"\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}|\|")


def is_refusal(text):
    return bool(text) and bool(REFUSAL_RE.search(text))


def looks_like_log(text):
    return bool(text) and bool(LOG_STRUCTURE_RE.search(text))


# parsing

def _trim_at_log_section(resolution):
    cut = re.search(r"\n\s*(Input logs:|Output logs:)", resolution, re.IGNORECASE)
    return resolution[: cut.start()].strip() if cut else resolution


def parse_problem_resolution(text):
    """Return (problem_text, resolution_text) or (None) if unparseable.

    Handles three shapes seen in the data:
      1. "Problem Identified: X, How to resolve: Y"   (the normal case)
      2. "Problem Identified: X" with no "How to resolve:" label at all -
         the rest of the text is used as both problem and resolution context.
      3. No "Problem Identified:" label at all, just a bare phrase like
         "No following steps required." - treated as an implicit no-problem
         verdict.
    """
    m = PROBLEM_RESOLVE_RE.search(text)
    if m:
        problem = m.group(1).strip()
        resolution = _trim_at_log_section(m.group(2).strip())
        return problem, resolution

    m2 = re.search(r"Problem\s*Identified:\s*(.*)", text, re.IGNORECASE | re.DOTALL)
    if m2:
        rest = _trim_at_log_section(m2.group(1).strip())
        return rest, rest

    lowered = text.lower()
    if any(phrase in lowered for phrase in NO_ACTION_ONLY_PHRASES):
        return "No issues found", text.strip()

    return None, None


def load_dataset_entries(path):
    entries = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                entries.append({"id": line_no, "reference": "", "output_text": "", "parse_ok": False})
                continue
            output_text = row.get("output", "")
            problem, resolution = parse_problem_resolution(output_text)
            entries.append({
                "id": line_no,
                "reference": row.get("input", ""),
                "output_text": output_text,
                "problem": problem,
                "resolution": resolution,
                "parse_ok": problem is not None,
            })
    return entries


def read_text_file(path):
    """Read a .txt file, or extract plain text from a .docx (paragraph by
    paragraph, so line-based parsing below still works)."""
    if path.lower().endswith(".docx"):
        with zipfile.ZipFile(path) as z:
            xml = z.read("word/document.xml").decode("utf-8", errors="replace")
        paragraphs = re.findall(r"<w:p[ >].*?</w:p>", xml, re.DOTALL)

        def para_text(p):
            p = re.sub(r"<w:br\s*/?>", "\n", p)
            p = re.sub(r"<w:tab\s*/?>", "\t", p)
            return "".join(re.findall(r"<w:t[^>]*>([^<]*)</w:t>", p))

        return "\n".join(para_text(p) for p in paragraphs)

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


DATASET_GROUP_HEADER_RE = re.compile(
    r"^=+\s*Group\s+(\d+)\s*\(size:\s*\d+\)\s*=+\s*$", re.IGNORECASE | re.MULTILINE
)


def load_reference_groups(path):
    """Load a raw log source file (e.g. 'Testing Dataset.txt', with
    '=== Group N (size: X) ===' blocks) keyed by group number, so it can be
    joined into testing-file entries that carry no log text of their own."""
    text = read_text_file(path)
    matches = list(DATASET_GROUP_HEADER_RE.finditer(text))
    groups = {}
    for i, m in enumerate(matches):
        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        block = re.split(r"\n=+\s*\n", text[start:end])[0]
        groups[m.group(1)] = block.strip()
    return groups


def split_groups(text):
    """Split raw testing-file text into blocks, one per Group header."""
    matches = list(GROUP_HEADER_RE.finditer(text))
    blocks = []
    for i, m in enumerate(matches):
        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        blocks.append((m.group(2), text[start:end]))
    return blocks


def load_testing_entries(path, use_pre_detections, reference_groups=None):
    text = read_text_file(path)
    reference_groups = reference_groups or {}

    entries = []
    for group_id, block in split_groups(text):
        # strip trailing separator lines
        block = re.split(r"\n=+\s*\n", block)[0]

        pre_detection = None
        if use_pre_detections:
            pm = re.search(r"Pre-detections:\s*(.*)", block, re.IGNORECASE)
            if pm:
                pre_detection = pm.group(1).strip().splitlines()[0].strip()

        log_lines = "\n".join(LOG_LINE_RE.findall(block))
        external_ref = reference_groups.get(group_id)

        # text after "Model response:" marker, else whole block
        mr = re.search(r"Model response:\s*(.*)", block, re.IGNORECASE | re.DOTALL)
        output_text = mr.group(1) if mr else block

        problem, resolution = parse_problem_resolution(output_text)

        # reference text for hallucination checks
        reference_parts = [p for p in (log_lines, external_ref, pre_detection) if p]
        reference = "\n".join(reference_parts)

        entries.append({
            "id": group_id,
            "reference": reference,
            "output_text": output_text,
            "problem": problem,
            "resolution": resolution,
            "parse_ok": problem is not None,
        })
    return entries


# scoring

def classify_reference(reference_text):
    """Return (expected_verdict, category) from reference/log text.

    expected_verdict is 'problem', 'no_problem', or None if the reference
    text is empty/uninformative (can't be graded for detection accuracy).
    """
    if not reference_text or not reference_text.strip():
        return None, None

    text_lower = reference_text.lower()
    for category, spec in CATEGORIES.items():
        for pattern in spec["indicators"]:
            if re.search(pattern, text_lower):
                return "problem", category

    for pattern in BENIGN_INDICATORS:
        if re.search(pattern, text_lower):
            return "no_problem", None

    # not confidently gradable
    return None, None


def model_verdict(problem_text):
    if problem_text is None:
        return None
    lowered = problem_text.lower()
    for phrase in NO_PROBLEM_PHRASES:
        if phrase in lowered:
            return "no_problem"
    return "problem"


def is_degenerate(text):
    if not text or not text.strip():
        return True
    return bool(DEGENERATE_RE.search(text))


def resolution_is_relevant(resolution_text, category):
    if not resolution_text or category is None:
        return None
    lowered = resolution_text.lower()
    return any(term in lowered for term in CATEGORIES[category]["resolution_terms"])


# known tools, not hallucination evidence
KNOWN_TOOLS = {
    "sfc.exe", "dism.exe", "chkdsk.exe", "services.msc", "dcomcnfg.exe",
    "taskmgr.exe", "perfmon.exe", "eventvwr.exe", "mdsched.exe", "regedit.exe",
    "msconfig.exe", "resmon.exe", "devmgmt.msc",
}


def _hex_matches_reference(hex_token, reference_lower):
    """True if a hex code's sign-extended, unsigned, or signed 32-bit
    decimal form appears in the reference (common Windows error-code
    formats: NTSTATUS/HRESULT shown as decimal in the log, hex in prose)."""
    digits = hex_token.split("0x", 1)[-1]
    if digits and digits in reference_lower:
        return True
    try:
        unsigned_val = int(digits, 16)
    except ValueError:
        return False
    signed_val = unsigned_val - 0x100000000 if unsigned_val >= 0x80000000 else unsigned_val
    return str(unsigned_val) in reference_lower or str(signed_val) in reference_lower


def find_fabricated_entities(problem_text, reference_text):
    """Entities named in the PROBLEM statement that don't appear
    anywhere in the reference/log text."""
    if not reference_text or not reference_text.strip():
        return []
    reference_lower = reference_text.lower()
    fabricated = []
    for kind, pattern in ENTITY_CHECKS:
        for match in pattern.findall(problem_text or ""):
            match_lower = match.lower()
            if match_lower in KNOWN_TOOLS or match_lower in reference_lower:
                continue
            if kind == "hex" and _hex_matches_reference(match_lower, reference_lower):
                continue
            fabricated.append(match)
    return fabricated


def score_entries(entries, mode):
    stats = Counter()
    stats["total"] = len(entries)

    for e in entries:
        output_raw = e.get("output_text") or ""

        if mode == "dataset" and is_refusal(output_raw):
            stats["refusal_total"] += 1
            if looks_like_log(e["reference"]):
                stats["refusal_incorrect"] += 1
            else:
                stats["refusal_correct"] += 1
            continue

        if not e["parse_ok"]:
            stats["parse_failures"] += 1
            continue

        full_output = (e.get("problem") or "") + " " + (e.get("resolution") or "")

        if is_instruction_echo(full_output):
            # placeholder scaffold echo
            stats["instruction_echo"] += 1
            stats["hallucination_graded"] += 1
            stats["hallucination_flagged"] += 1
            continue

        if mode == "dataset" and e["reference"].strip() and not looks_like_log(e["reference"]):
            # missed refusal
            stats["missed_refusal"] += 1
            continue

        if is_degenerate(full_output):
            stats["malformed"] += 1
            continue

        expected_verdict, category = classify_reference(e["reference"])
        actual_verdict = model_verdict(e["problem"])

        if expected_verdict is None:
            stats["ungraded_no_reference"] += 1
        else:
            stats["detection_graded"] += 1
            if actual_verdict == expected_verdict:
                stats["detection_correct"] += 1

            if expected_verdict == "problem" and actual_verdict == "problem":
                relevant = resolution_is_relevant(e["resolution"], category)
                if relevant is not None:
                    stats["resolution_graded"] += 1
                    if relevant:
                        stats["resolution_correct"] += 1

        fabricated = find_fabricated_entities(e.get("problem"), e["reference"])
        if e["reference"].strip():
            stats["hallucination_graded"] += 1
            if fabricated:
                stats["hallucination_flagged"] += 1

    return stats


def print_report(stats):
    total = stats["total"]
    print("\n" + "=" * 60)
    print("CORRECTNESS REPORT")
    print("=" * 60)
    print(f"Total entries:              {total}")
    print(f"Parse failures:             {stats['parse_failures']}"
          f" ({pct(stats['parse_failures'], total)})")
    print(f"Malformed/degenerate:       {stats['malformed']}"
          f" ({pct(stats['malformed'], total)})")
    print(f"Ungraded (no reference):    {stats['ungraded_no_reference']}"
          f" ({pct(stats['ungraded_no_reference'], total)})")
    if stats["refusal_total"] or stats["missed_refusal"]:
        print("-" * 60)
        print(f"Off-topic refusal accuracy: {pct(stats['refusal_correct'], stats['refusal_total'])}"
              f"  ({stats['refusal_correct']}/{stats['refusal_total']} graded)")
        print(f"Missed refusals:            {stats['missed_refusal']}"
              " (off-topic input, model answered anyway)")
    print("-" * 60)
    print(f"Detection accuracy (graded): {pct(stats['detection_correct'], stats['detection_graded'])}"
          f"  ({stats['detection_correct']}/{stats['detection_graded']} graded)")
    print(f"Detection accuracy (of all): {pct(stats['detection_correct'], total)}"
          f"  ({stats['detection_correct']}/{total} total)"
          " - accounts for echo/parse-failure/ungraded entries too")
    print(f"Resolution relevance:       {pct(stats['resolution_correct'], stats['resolution_graded'])}"
          f"  ({stats['resolution_correct']}/{stats['resolution_graded']} graded)")
    print(f"Hallucination rate:         {pct(stats['hallucination_flagged'], stats['hallucination_graded'])}"
          f"  ({stats['hallucination_flagged']}/{stats['hallucination_graded']} graded)")
    print(f"  of which template echo:   {stats['instruction_echo']}"
          " (regurgitated the prompt's placeholder text instead of answering)")
    print("=" * 60 + "\n")


def pct(n, d):
    if not d:
        return "n/a"
    return f"{100 * n / d:.1f}%"


# entry point

def ask(prompt, choices=None):
    while True:
        answer = input(prompt).strip().lower()
        if choices is None or answer in choices:
            return answer
        print(f"Please enter one of: {', '.join(choices)}")


def main():
    print("Correctness calculator for LM log-analysis responses")
    mode = ask(
        "Calculating results for a (1) dataset or (2) testing responses? [1/2]: ",
        choices={"1", "2", "dataset", "testing"},
    )

    if mode in ("1", "dataset"):
        path = input("Path to the dataset .jsonl file: ").strip().strip('"')
        entries = load_dataset_entries(path)
        run_mode = "dataset"
    else:
        use_pre = ask(
            "Does this testing file use correlated groups? [y/n]: ",
            choices={"y", "n"},
        ) == "y"
        path = input("Path to the testing response file: ").strip().strip('"')

        reference_groups = None
        has_ref = ask(
            "Is there a separate raw log file (e.g. 'Testing Dataset.txt', "
            "with '=== Group N (size: X) ===' blocks) to join in by group "
            "number as reference text? [y/n]: ",
            choices={"y", "n"},
        ) == "y"
        if has_ref:
            ref_path = input("Path to that raw log reference file: ").strip().strip('"')
            reference_groups = load_reference_groups(ref_path)

        entries = load_testing_entries(path, use_pre, reference_groups)
        run_mode = "testing"

    if not entries:
        print("No entries were parsed from that file - check the path/format.")
        sys.exit(1)

    stats = score_entries(entries, run_mode)
    print_report(stats)


if __name__ == "__main__":
    main()
