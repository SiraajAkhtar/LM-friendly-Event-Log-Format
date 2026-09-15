import csv
import json
import os
import re
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone

ROOT = os.path.normpath(os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..", "Testing Script", "dist", "Results", "With all tools",
))

DIRECT_ID_WINDOW = timedelta(minutes=30)
PROXIMITY_WINDOW = timedelta(seconds=4)

TS_ISO_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?([+-]\d{2}:\d{2})$"
)


def long_path(path):
    """Windows MAX_PATH (260 chars) can make open()/os.path.exists() silently fail (or
    raise FileNotFoundError) for paths this deeply nested even though the file is real.
    The \\\\?\\ prefix opts into the extended-length path API and sidesteps it."""
    if os.name == "nt" and not path.startswith("\\\\?\\"):
        return "\\\\?\\" + os.path.abspath(path).replace("/", "\\")
    return path


def read_text_with_retry(path, attempts=5, delay=0.5):
    """OneDrive Files On-Demand placeholders occasionally aren't hydrated yet on first
    touch, which can make a just-listed file transiently fail to open. Retry briefly
    rather than treating that as 'file has zero records'."""
    last_exc = None
    for _ in range(attempts):
        try:
            with open(long_path(path), "r", encoding="utf-8-sig") as f:
                return f.read()
        except (FileNotFoundError, PermissionError, OSError) as exc:
            last_exc = exc
            time.sleep(delay)
    raise last_exc


def parse_iso(text):
    """Parses .NET's DateTimeOffset JSON format (up to 7 fractional digits) into an
    aware UTC datetime with microsecond precision (Python's max)."""
    m = TS_ISO_RE.match(text)
    if not m:
        raise ValueError(f"Unrecognized timestamp: {text}")
    base, frac, offset = m.groups()
    dt = datetime.strptime(base, "%Y-%m-%dT%H:%M:%S")
    if frac:
        micros = int((frac + "000000")[:6])
        dt = dt.replace(microsecond=micros)
    sign = 1 if offset[0] == "+" else -1
    oh, om = int(offset[1:3]), int(offset[4:6])
    dt = dt.replace(tzinfo=timezone(sign * timedelta(hours=oh, minutes=om)))
    return dt.astimezone(timezone.utc)


def parse_csv_timestamp(text):
    # timestamp format
    dt = datetime.strptime(text, "%d/%m/%y %H:%M:%S")
    return dt.replace(tzinfo=timezone.utc)


def load_sidecar(path):
    records = []
    if not os.path.exists(long_path(path)):
        return records
    content = read_text_with_retry(path)
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        obj = json.loads(line)
        records.append({
            "timestamp": parse_iso(obj["Timestamp"]),
            "description": obj["Description"],
            "kind": obj["Kind"],
            "logon_id": obj["LogonId"],
            "process_id": obj["ProcessId"],
            "interface_guid": obj["InterfaceGuid"],
        })
    return records


def ids_of(record):
    if record is None:
        return (None, None, None)
    return (record["logon_id"], record["process_id"], record["interface_guid"])


def join_ground_truth(csv_rows, sidecar_records):
    """Positional alignment: csv_rows[i] and sidecar_records[i] come from the same
    single OnCaptured() call for the same real event, each written by its own
    single-writer channel in file order. Only trustworthy if row counts and
    descriptions line up -- checked by the caller (see verify_alignment) first."""
    return list(sidecar_records)


def verify_alignment(csv_rows, sidecar_records):
    if len(csv_rows) != len(sidecar_records):
        return False, f"row count mismatch: {len(csv_rows)} csv vs {len(sidecar_records)} sidecar"
    for i, (c, s) in enumerate(zip(csv_rows, sidecar_records)):
        if c["description"] != s["description"]:
            return False, f"description mismatch at index {i}: {c['description']!r} vs {s['description']!r}"
    return True, "ok"


def to_events(csv_rows, joined):
    events = []
    for row, rec in zip(csv_rows, joined):
        lid, pid, guid = ids_of(rec)
        events.append({
            "timestamp": row["timestamp"],
            "logon_id": lid,
            "process_id": pid,
            "interface_guid": guid,
        })
    return events




def find_links(events):
    """events: list of dicts with keys timestamp, logon_id, process_id, interface_guid.
    Returns a set of frozenset({i, j}) pairs that are linked, mirroring
    EventCorrelationEngine.FindLinks (direct-id within 30 min, else proximity within
    4s, a shared-id pair never double-counted as proximity)."""
    order = sorted(range(len(events)), key=lambda i: events[i]["timestamp"])

    def group_by(key):
        groups = defaultdict(list)
        for i in order:
            v = events[i][key]
            if v is not None:
                groups[v].append(i)
        return groups

    links = set()

    for key in ("logon_id", "process_id", "interface_guid"):
        for _, members in group_by(key).items():
            for a, b in zip(members, members[1:]):
                if events[b]["timestamp"] - events[a]["timestamp"] <= DIRECT_ID_WINDOW:
                    links.add(frozenset((a, b)))

    def shares_any_id(a, b):
        ea, eb = events[a], events[b]
        return (
            (ea["logon_id"] is not None and ea["logon_id"] == eb["logon_id"])
            or (ea["process_id"] is not None and ea["process_id"] == eb["process_id"])
            or (ea["interface_guid"] is not None and ea["interface_guid"] == eb["interface_guid"])
        )

    n = len(order)
    for oi in range(n):
        i = order[oi]
        for oj in range(oi + 1, n):
            j = order[oj]
            if events[j]["timestamp"] - events[i]["timestamp"] > PROXIMITY_WINDOW:
                break
            if shares_any_id(i, j):
                continue
            links.add(frozenset((i, j)))

    return links


def assign_groups(events):
    parent = list(range(len(events)))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        a, b = find(a), find(b)
        if a != b:
            parent[a] = b

    links = find_links(events)
    for link in links:
        a, b = tuple(link)
        union(a, b)

    members_by_root = defaultdict(list)
    for i in range(len(events)):
        members_by_root[find(i)].append(i)

    n_groups = sum(1 for m in members_by_root.values() if len(m) > 1)
    n_uncorrelated = sum(1 for m in members_by_root.values() if len(m) == 1)
    return n_groups, n_uncorrelated, members_by_root
