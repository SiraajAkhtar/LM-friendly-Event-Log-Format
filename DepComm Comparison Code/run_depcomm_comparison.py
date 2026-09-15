import csv
import glob
import os
import random
import sys
from urllib.parse import unquote

# pass a seed
random.seed(42)

HERE = os.path.dirname(os.path.abspath(__file__))
import event_log_io as cs  
                            

from depcomm_wrapper import depcomm_group_logs  

ROOT = cs.ROOT  
TIME_WINDOW_SECONDS = 4  


def deserialize_context(serialized):
    context = {}
    if not serialized:
        return context
    for pair in serialized.split(";"):
        if not pair:
            continue
        key, _, value = pair.partition("=")
        if not _:
            continue
        context[unquote(key)] = unquote(value)
    return context


def load_csv_with_context(path):
    """Same CSV shape as correlation_scorer.load_csv, but also decodes the Context
    column (correlation_scorer discards it -- it never needed process/user names)."""
    content = cs.read_text_with_retry(path)
    reader = csv.reader(content.splitlines())
    next(reader, None)
    rows = []
    for fields in reader:
        if len(fields) < 3:
            continue
        rows.append({
            "timestamp": cs.parse_csv_timestamp(fields[0]),
            "description": fields[1],
            "context": deserialize_context(fields[2]),
        })
    return rows


def to_depcomm_logs(csv_rows):
    """EventLogCollector's CSV has no raw numeric EventID (EventCatalog deliberately
    never exposes one) -- so event_id is always None here and that rule of
    depcomm_wrapper simply never fires, honestly reflecting what this schema
    actually has. process/user come from the same named Context fields a person
    reading the CSV would use to tell "who/what did this" apart -- independent of
    EventCorrelationEngine's own LogonId/ProcessId/InterfaceGuid, which are never
    written to the CSV or its Context at all."""
    logs = []
    for i, row in enumerate(csv_rows):
        ctx = row["context"]
        process = ctx.get("NewProcessName") or ctx.get("ParentProcessName") or ""
        user = ctx.get("SubjectUserName") or ctx.get("TargetUserName") or ""
        logs.append({
            "idx": i,
            "ts": row["timestamp"],
            "event_id": None,
            "process": process,
            "user": user,
            "text": row["description"],
        })
    return logs


def our_labels(csv_rows_no_ctx, sidecar_records):
    """Ground-truth EventCorrelationEngine grouping (via the positionally-verified
    join correlation_scorer.py already validated), as a per-index group-id array."""
    truth = cs.join_ground_truth(csv_rows_no_ctx, sidecar_records)
    events = cs.to_events(csv_rows_no_ctx, truth)
    _, _, members_by_root = cs.assign_groups(events)
    labels = [None] * len(csv_rows_no_ctx)
    for root, members in members_by_root.items():
        for i in members:
            labels[i] = root
    return labels


def depcomm_labels(depcomm_groups, n):
    labels = [None] * n
    for group_id, group in enumerate(depcomm_groups):
        for log in group:
            labels[log["idx"]] = group_id
    return labels


def rand_index(labels_a, labels_b):
    """Fraction of event pairs the two clusterings agree on (both 'same group' or
    both 'different group'). Standard pairwise clustering-agreement metric."""
    n = len(labels_a)
    if n < 2:
        return None
    agree = 0
    total = 0
    for i in range(n):
        la_i, lb_i = labels_a[i], labels_b[i]
        for j in range(i + 1, n):
            same_a = la_i == labels_a[j]
            same_b = lb_i == labels_b[j]
            if same_a == same_b:
                agree += 1
            total += 1
    return round(100 * agree / total, 1)


def count_groups(labels):
    from collections import Counter
    counts = Counter(labels)
    groups = sum(1 for c in counts.values() if c > 1)
    singletons = sum(1 for c in counts.values() if c == 1)
    return groups, singletons


def main():
    pairs = sorted(glob.glob(os.path.join(ROOT, "*", "My format", "*.csv")))
    if not pairs:
        print(f"No CSV files found under: {ROOT}")
        sys.exit(1)

    rows_out = []
    for csv_path in pairs:
        folder = os.path.basename(os.path.dirname(os.path.dirname(csv_path)))
        scenario_id, _, scenario_name = folder.partition(" - ")
        sidecar_path = os.path.splitext(csv_path)[0] + ".correlation.ndjson"

        csv_rows_ctx = load_csv_with_context(csv_path)
        csv_rows_plain = [{"timestamp": r["timestamp"], "description": r["description"]} for r in csv_rows_ctx]
        sidecar_records = cs.load_sidecar(sidecar_path)

        aligned, msg = cs.verify_alignment(csv_rows_plain, sidecar_records)
        if not aligned:
            print(f"!! alignment check failed for {folder}: {msg}")
            continue

        n = len(csv_rows_ctx)

        labels_ours = our_labels(csv_rows_plain, sidecar_records)
        groups_ours, singletons_ours = count_groups(labels_ours)

        depcomm_logs = to_depcomm_logs(csv_rows_ctx)
        depcomm_groups = depcomm_group_logs(depcomm_logs, time_window_seconds=TIME_WINDOW_SECONDS)
        labels_dc = depcomm_labels(depcomm_groups, n)
        groups_dc, singletons_dc = count_groups(labels_dc)

        agreement = rand_index(labels_ours, labels_dc)

        row = {
            "scenario": scenario_id,
            "scenario_name": scenario_name,
            "n": n,
            "groups_ours": groups_ours,
            "singletons_ours": singletons_ours,
            "groups_depcomm": groups_dc,
            "singletons_depcomm": singletons_dc,
            "pairwise_agreement_pct": agreement,
        }
        rows_out.append(row)

        print(f"{scenario_id:<3} {scenario_name:<48} n={n:>4}  "
              f"ours: {groups_ours} grp / {singletons_ours} single   "
              f"depcomm: {groups_dc} grp / {singletons_dc} single   "
              f"agreement={agreement}%")

    avg_agreement = round(sum(r["pairwise_agreement_pct"] for r in rows_out) / len(rows_out), 1)
    print()
    print(f"=== Overall: average pairwise agreement across {len(rows_out)} scenarios "
          f"(depcomm time_window_seconds={TIME_WINDOW_SECONDS}) = {avg_agreement}% ===")

    results_dir = os.path.join(HERE, "Results")
    os.makedirs(results_dir, exist_ok=True)
    csv_out = os.path.join(results_dir, "depcomm_agreement_by_scenario.csv")
    with open(csv_out, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows_out[0].keys()))
        writer.writeheader()
        writer.writerows(rows_out)
    print(f"\nWrote {csv_out}")


if __name__ == "__main__":
    main()
