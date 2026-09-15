import json
import os
import random
import re
import time
from datetime import timedelta

import requests

# configuration

API_KEY = os.environ.get("OPENROUTER_API_KEY")  # environment variable
API_URL = "https://openrouter.ai/api/v1/chat/completions"
MODEL = "anthropic/claude-sonnet-4"

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_JSONL = os.environ.get(
    "OUTPUT_JSONL", os.path.join(SCRIPT_DIR, "gemma_windows_log_dataset.jsonl")
)

TOTAL_EXAMPLES = int(os.environ.get("TOTAL_EXAMPLES", 5000))
BATCH_SIZE = int(os.environ.get("BATCH_SIZE", 15))  # logs generated + analyzed per API call
MAX_TOKENS = 4096
SLEEP_BETWEEN_CALLS = 15  # seconds, adjust to the applicable OpenRouter rate limit
MAX_RETRIES_PER_BATCH = 3
MAX_CONSECUTIVE_FAILURES = 5  # abort the run if this many batches in a row fail outright

# system prompt for training examples
TRAINING_SYSTEM_PROMPT = (
    "You are a Windows event log analyst. Given a single Windows event log "
    "entry, identify the underlying problem and explain how to resolve it."
)

# log entry examples
FEW_SHOT_EXAMPLES = [
    "14/11/20 8:25:14, error prevented file from opening, Machine was Laptop-1MK error was "
    "Access is denied and file was C:\\WINDOWS\\system32\\config\\systemprofile\\AppData\\Local\\"
    "TileDataLayer\\Database\\EDB.log",
    "14/11/14 8:41:59, software protection restart scheduled, set to 14/11/14 at 11:28 on Laptop-1MK",
    "27/11/20 7:03:12, could not download update, relevant files were not available on DESKTOP-SEJ",
]

CATEGORY_HINTS = [
    "file access errors (permission denied, corrupted files, missing files)",
    "Windows Update failures (download errors, install errors, pending restarts)",
    "software protection / licensing restart scheduling",
    "performance monitor (PerfMon) metrics: CPU, memory, disk, network counters",
    "service failures and crashes (Windows services failing to start or stopping unexpectedly)",
    "disk space and storage warnings (low disk space, disk errors, SMART warnings)",
    "network connectivity issues (DNS failures, DHCP issues, VPN disconnects)",
    "Windows Defender / security alerts (malware detection, definition update failures)",
    "driver and hardware issues (driver install failures, device errors)",
    "print spooler and printer errors",
    "Group Policy processing errors",
    "scheduled task failures",
    "application crashes and unhandled exceptions",
    "user profile and login issues (slow logon, profile corruption)",
    "memory pressure and application hangs / not responding",
]

ENTRY_RE = re.compile(
    r"<<<ENTRY>>>\s*LOG:\s*(.*?)\s*PROBLEM:\s*(.*?)\s*RESOLUTION:\s*(.*?)\s*<<<END>>>",
    re.DOTALL,
)


def build_generation_prompt(batch_size):
    categories = random.sample(CATEGORY_HINTS, k=min(4, len(CATEGORY_HINTS)))
    examples_block = "\n".join(f"- {ex}" for ex in FEW_SHOT_EXAMPLES)
    categories_block = "\n".join(f"- {c}" for c in categories)

    return f"""You are simulating realistic Windows OS event log entries for a fine-tuning dataset.

Each log entry has exactly three CSV fields, in this order: Date/time, Context, Event Description.
- Date/time format: DD/MM/YY H:MM:SS (24-hour clock)
- Context: a short lowercase phrase summarizing the type of event
- Event Description: one sentence with specifics (machine name, error code/message, file path, service name,
  or metric values as relevant). Do not put commas inside the Event Description field.

Here are some example logs in the format:
{examples_block}

Generate {batch_size} new, and different log entries. 

For each log entry, identify the problem and explain
concretely how to resolve it.

Do not provide extra commentary or no numbering:


"""


def call_openrouter(prompt):
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json",
    }
    data = {
        "model": MODEL,
        "max_tokens": MAX_TOKENS,
        "messages": [{"role": "user", "content": prompt}],
    }

    try:
        response = requests.post(API_URL, headers=headers, data=json.dumps(data), timeout=120)
        response_json = response.json()
    except Exception as e:
        print(f"  ! request exception: {e}")
        return None

    if response.status_code == 200 and "choices" in response_json:
        return response_json["choices"][0]["message"]["content"]

    print(f"  ! API error: {response_json}")
    return None


def parse_batch_response(text):
    entries = []
    for log, problem, resolution in ENTRY_RE.findall(text):
        log = " ".join(log.split())
        problem = " ".join(problem.split()).rstrip(".")
        resolution = " ".join(resolution.split()).rstrip(".")
        if log and problem and resolution:
            entries.append((log, problem, resolution))
    return entries


def build_training_example(log, problem, resolution):
    assistant_content = f"Problem Identified: {problem}. How to resolve: {resolution}."
    return {
        "messages": [
            {"role": "system", "content": TRAINING_SYSTEM_PROMPT},
            {"role": "user", "content": log},
            {"role": "model", "content": assistant_content},
        ]
    }


def count_existing_examples(path):
    if not os.path.exists(path):
        return 0
    with open(path, "r", encoding="utf-8") as f:
        return sum(1 for line in f if line.strip())


def main():
    if not API_KEY:
        print("Error: API key not inserted.")
        return

    beginning_time = time.time()

    existing = count_existing_examples(OUTPUT_JSONL)
    remaining = TOTAL_EXAMPLES - existing
    if remaining <= 0:
        print(f"Already have {existing} examples in {OUTPUT_JSONL}, target of {TOTAL_EXAMPLES} reached.")
        return

    mode = "a" if existing else "w"
    print(f"Resuming from {existing} existing examples. Need {remaining} more." if existing
          else f"Starting fresh. Target: {TOTAL_EXAMPLES} examples.")

    seen_logs = set()
    if existing:
        with open(OUTPUT_JSONL, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    seen_logs.add(obj["messages"][1]["content"])
                except (json.JSONDecodeError, KeyError, IndexError):
                    continue

    written = existing
    consecutive_failures = 0
    with open(OUTPUT_JSONL, mode, encoding="utf-8") as outfile:
        batch_num = 0
        while written < TOTAL_EXAMPLES:
            batch_num += 1
            print(f"\nBatch {batch_num} (have {written}/{TOTAL_EXAMPLES})...")

            prompt = build_generation_prompt(BATCH_SIZE)

            parsed = []
            for attempt in range(1, MAX_RETRIES_PER_BATCH + 1):
                result = call_openrouter(prompt)
                if result:
                    parsed = parse_batch_response(result)
                    if parsed:
                        break
                print(f"  attempt {attempt} produced no usable entries, retrying...")
                time.sleep(5)

            if not parsed:
                consecutive_failures += 1
                print(f"  ! batch failed after retries, skipping. "
                      f"({consecutive_failures}/{MAX_CONSECUTIVE_FAILURES} consecutive failures)")
                if consecutive_failures >= MAX_CONSECUTIVE_FAILURES:
                    print(f"\nAborting: {MAX_CONSECUTIVE_FAILURES} batches in a row failed "
                          f"(likely an API outage or bad API key). {written} examples were saved.")
                    break
                continue

            consecutive_failures = 0
            new_count = 0
            for log, problem, resolution in parsed:
                if log in seen_logs:
                    continue
                seen_logs.add(log)
                example = build_training_example(log, problem, resolution)
                outfile.write(json.dumps(example, ensure_ascii=False) + "\n")
                written += 1
                new_count += 1
                if written >= TOTAL_EXAMPLES:
                    break

            outfile.flush()
            print(f"  + added {new_count} new examples (total {written}/{TOTAL_EXAMPLES})")

            if written < TOTAL_EXAMPLES:
                time.sleep(SLEEP_BETWEEN_CALLS)

    print(f"\nDone. {written} examples written to:\n{OUTPUT_JSONL}")
    finish = time.time()
    print("Total time:", str(timedelta(seconds=finish - beginning_time)))


if __name__ == "__main__":
    main()
