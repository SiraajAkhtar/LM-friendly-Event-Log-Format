import csv
import os
from pathlib import Path
from typing import Iterator, NamedTuple
from urllib.parse import unquote

from noise_filter import is_noise

MAX_FIELD_CHARS = int(os.environ.get("MAX_FIELD_CHARS", "4000"))


class Entry(NamedTuple):
    scenario: str
    source_file: str
    row_index: int
    prompt_text: str
    raw_text: str
    is_noise: bool


def _truncate(value: str, limit: int = MAX_FIELD_CHARS) -> str:
    if value is None:
        return ""
    if len(value) > limit:
        return value[:limit] + f"...[truncated {len(value) - limit} chars]"
    return value


def _is_placeholder_file(path: Path) -> bool:
    try:
        with open(path, "r", encoding="utf-8-sig", errors="replace") as f:
            first = f.readline()
    except OSError:
        return True
    return "No events found" in first or "No events were found" in first


def _read_rows(path: Path):
    """header, row for every real data row in a CSV file, nothing at all"""
    if not path.exists() or path.stat().st_size == 0 or _is_placeholder_file(path):
        return
    with open(path, "r", encoding="utf-8-sig", newline="", errors="replace") as f:
        reader = csv.reader(f)
        try:
            header = next(reader)
        except StopIteration:
            return
        for row in reader:
            if not row or all(not c.strip() for c in row):
                continue
            if len(row) < len(header):
                row = row + [""] * (len(header) - len(row))
            elif len(row) > len(header):
                row = row[: len(header)]
            yield header, row


def _field_value_prompt(header, row) -> str:
    return "\n".join(f"{k}: {_truncate(v)}" for k, v in zip(header, row))


def _iter_generic_csv(path: Path, scenario_name: str):
    for i, (header, row) in enumerate(_read_rows(path)):
        raw_text = " ".join(row)
        prompt_text = _field_value_prompt(header, row)
        yield scenario_name, path.name, i, prompt_text, raw_text


def _iter_my_format(scenario_dir: Path):
    folder = scenario_dir / "My format"
    for path in sorted(folder.glob("events_*.csv")):
        for i, (header, row) in enumerate(_read_rows(path)):
            row = [unquote(c) if c else c for c in row]
            values = dict(zip(header, row))
            prompt_text = ", ".join(
                _truncate(values.get(col, "")) for col in ("Timestamp", "Description", "Context")
            )
            raw_text = " ".join(row)
            yield scenario_dir.name, path.name, i, prompt_text, raw_text


def _iter_channel_csvs(scenario_dir: Path, subfolder: str):
    folder = scenario_dir / subfolder
    if not folder.exists():
        return
    for path in sorted(folder.glob("*.csv")):
        yield from _iter_generic_csv(path, scenario_dir.name)


def _iter_original(scenario_dir: Path):
    yield from _iter_channel_csvs(scenario_dir, "Original")


def _iter_sysmon(scenario_dir: Path):
    yield from _iter_channel_csvs(scenario_dir, "Sysmon")


def _iter_silketw(scenario_dir: Path):
    path = scenario_dir / "SilkETW" / "silketw_output.csv"
    yield from _iter_generic_csv(path, scenario_dir.name)


def _iter_winlogbeat(scenario_dir: Path):
    path = scenario_dir / "Winlogbeat" / "winlogbeat_output.csv"
    yield from _iter_generic_csv(path, scenario_dir.name)


_ITERATORS = {
    "my_format": _iter_my_format,
    "original": _iter_original,
    "silketw": _iter_silketw,
    "sysmon": _iter_sysmon,
    "winlogbeat": _iter_winlogbeat,
}


def iter_entries(scenario_dir: Path, fmt: str) -> Iterator[Entry]:
    for scenario_name, source_file, row_index, prompt_text, raw_text in _ITERATORS[fmt](scenario_dir):
        is_noise_ = is_noise(f"{raw_text} {prompt_text}")
        yield Entry(
            scenario=scenario_name,
            source_file=source_file,
            row_index=row_index,
            prompt_text=prompt_text,
            raw_text=raw_text,
            is_noise=is_noise_,
        )


def iter_net_entries(scenario_dir: Path, fmt: str) -> Iterator[Entry]:
    """Same as iter_entries but skips harness-noise rows"""
    for entry in iter_entries(scenario_dir, fmt):
        if not entry.is_noise:
            yield entry
