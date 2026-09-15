from __future__ import annotations

import csv
import json
import os
import shutil
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from . import config
from .context import TestContext
from .export_original import export_original_logs
from .powershell import run_ps


def _long_path(path: Path) -> str:
    s = str(path.resolve()).replace("/", "\\")
    if s.startswith("\\\\?\\"):
        return s
    if s.startswith("\\\\"):
        return "\\\\?\\UNC\\" + s[2:]
    return "\\\\?\\" + s


def _load_json_records(path: Path) -> List[dict]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return []
    if not text:
        return []
    try:
        obj = json.loads(text)
        if isinstance(obj, list):
            return [x for x in obj if isinstance(x, dict)]
        if isinstance(obj, dict):
            return [obj]
    except (ValueError, TypeError):
        pass
    records: List[dict] = []
    for line in text.splitlines():
        line = line.strip().rstrip(",")
        if not line:
            continue
        try:
            obj = json.loads(line)
        except (ValueError, TypeError):
            records.append({"_raw": line})
            continue
        if isinstance(obj, dict):
            records.append(obj)
    return records


def _write_csv(records: List[dict], csv_path: Path) -> int:
    fieldnames: List[str] = []
    seen = set()
    for rec in records:
        for key in rec.keys():
            if key not in seen:
                seen.add(key)
                fieldnames.append(key)
    with open(_long_path(csv_path), "w", encoding="utf-8", newline="") as f:
        if not fieldnames:
            return 0
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore", restval="")
        writer.writeheader()
        for rec in records:
            row = {}
            for key in fieldnames:
                val = rec.get(key, "")
                if isinstance(val, (dict, list)):
                    val = json.dumps(val, default=str, ensure_ascii=False)
                row[key] = val
            writer.writerow(row)
    return len(records)


@dataclass
class ComparisonTool:
    id: str
    label: str
    folder_name: str
    fix_hint: str
    is_available: Callable[[], Tuple[bool, str]]
    begin: Callable[[TestContext, Path], dict]
    stop: Callable[[TestContext, dict], None]
    export: Callable[[TestContext, Path, dict, datetime, datetime], None]


def _sysmon_available() -> Tuple[bool, str]:
    r = run_ps(f"(Get-Service -Name {config.SYSMON_SERVICE_NAME} -ErrorAction SilentlyContinue).Status")
    status = r.stdout.strip()
    if status.lower() == "running":
        return True, f"service {config.SYSMON_SERVICE_NAME} running"
    return False, f"service {config.SYSMON_SERVICE_NAME} not running (status: {status or 'not installed'})"


def _sysmon_begin(ctx: TestContext, out_dir: Path) -> dict:
    return {}


def _sysmon_stop(ctx: TestContext, state: dict) -> None:
    pass


def _sysmon_export(ctx: TestContext, out_dir: Path, state: dict, start: datetime, end: datetime) -> None:
    try:
        export_original_logs(start, end, out_dir, channels=[config.SYSMON_CHANNEL])
    except Exception as exc:  # noqa: BLE001
        ctx.note(f"[WARNING] Sysmon export failed: {exc}")


_SILKETW_START_SCRIPT = r"""
param(
    [Parameter(Mandatory=$true)][string]$ExePath,
    [Parameter(Mandatory=$true)][string]$OutFile
)
$argStr = "-t kernel -kk Process -ot file -p `"$OutFile`""
$p = Start-Process -FilePath $ExePath -ArgumentList $argStr -PassThru -WindowStyle Hidden
Write-Output $p.Id
"""


def _silketw_available() -> Tuple[bool, str]:
    if config.SILKETW_EXE.is_file():
        return True, str(config.SILKETW_EXE)
    return False, f"{config.SILKETW_EXE} not found"


def _start_background_process(ctx: TestContext, script: str, params: Dict[str, str], context: str) -> Optional[int]:
    result = ctx.run_script(script, params=params, context=context)
    lines = [l.strip() for l in result.stdout.splitlines() if l.strip()]
    if lines and lines[-1].isdigit():
        return int(lines[-1])
    ctx.note(f"[WARNING] {context}: no PID returned (stderr: {result.stderr.strip()!r})")
    return None


def _silketw_begin(ctx: TestContext, out_dir: Path) -> dict:
    tag = f"{ctx.test_id}_{uuid.uuid4().hex[:8]}"
    raw_file = ctx.scratch_dir / f"silketw_raw_{tag}.json"
    pid = _start_background_process(
        ctx,
        _SILKETW_START_SCRIPT,
        {"ExePath": str(config.SILKETW_EXE), "OutFile": str(raw_file)},
        context="start SilkETW capture",
    )
    time.sleep(2)  # etw startup
    return {"pid": pid, "raw_file": raw_file}


def _silketw_stop(ctx: TestContext, state: dict) -> None:
    pid = (state or {}).get("pid")
    if pid:
        ctx.run(f"Stop-Process -Id {pid} -Force -ErrorAction SilentlyContinue", context="stop SilkETW capture")


def _silketw_export(ctx: TestContext, out_dir: Path, state: dict, start: datetime, end: datetime) -> None:
    raw_file = (state or {}).get("raw_file")
    csv_path = out_dir / "silketw_output.csv"
    if not raw_file or not Path(raw_file).is_file() or Path(raw_file).stat().st_size == 0:
        ctx.note("[WARNING] No SilkETW output captured for this test.")
        return
    records = _load_json_records(Path(raw_file))
    kept = _write_csv(records, csv_path)
    if kept == 0:
        ctx.note("[WARNING] SilkETW captured a file but it contained no parseable events.")
    try:
        Path(raw_file).unlink(missing_ok=True)
    except OSError:
        pass


_WINLOGBEAT_START_SCRIPT = r"""
param(
    [Parameter(Mandatory=$true)][string]$ExePath,
    [Parameter(Mandatory=$true)][string]$ConfigPath,
    [Parameter(Mandatory=$true)][string]$DataPath
)
$argStr = "-c `"$ConfigPath`" --path.data `"$DataPath`""
$p = Start-Process -FilePath $ExePath -ArgumentList $argStr -PassThru -WindowStyle Hidden
Write-Output $p.Id
"""


def _winlogbeat_available() -> Tuple[bool, str]:
    if config.WINLOGBEAT_EXE.is_file():
        return True, str(config.WINLOGBEAT_EXE)
    return False, f"{config.WINLOGBEAT_EXE} not found"


def _winlogbeat_yaml(out_dir: Path) -> str:
    # bound backfill window
    channels = "\n".join(f'  - name: "{c}"\n    ignore_older: 10m' for c in config.WATCHED_CHANNELS)
    return (
        "winlogbeat.event_logs:\n"
        f"{channels}\n"
        "output.file:\n"
        f'  path: "{out_dir.as_posix()}"\n'
        '  filename: "winlogbeat_output"\n'
        "  rotate_every_kb: 102400\n"
        "logging.to_files: false\n"
        "logging.metrics.enabled: false\n"
    )


_WINLOGBEAT_FILE_PREFIX = "winlogbeat_output"


def _winlogbeat_begin(ctx: TestContext, out_dir: Path) -> dict:
    tag = f"{ctx.test_id}_{uuid.uuid4().hex[:8]}"
    yml_path = ctx.scratch_dir / f"winlogbeat_{tag}.yml"
    data_dir = ctx.scratch_dir / f"winlogbeat_data_{tag}"
    yml_path.write_text(_winlogbeat_yaml(out_dir), encoding="utf-8")

    pid = _start_background_process(
        ctx,
        _WINLOGBEAT_START_SCRIPT,
        {"ExePath": str(config.WINLOGBEAT_EXE), "ConfigPath": str(yml_path), "DataPath": str(data_dir)},
        context="start Winlogbeat capture",
    )
    time.sleep(2)  # attach delay
    return {"pid": pid, "yml_path": yml_path, "data_dir": data_dir}


def _winlogbeat_stop(ctx: TestContext, state: dict) -> None:
    pid = (state or {}).get("pid")
    if pid:
        ctx.run(f"Stop-Process -Id {pid} -Force -ErrorAction SilentlyContinue", context="stop Winlogbeat capture")


def _merge_and_trim_winlogbeat_output(
    raw_files: List[Path],
    csv_path: Path,
    start: datetime,
    end: datetime,
    margin_seconds: int = config.EXPORT_WINDOW_MARGIN_SECONDS,
) -> int:
    lo = (start - timedelta(seconds=margin_seconds)).replace(tzinfo=None)
    hi = (end + timedelta(seconds=margin_seconds)).replace(tzinfo=None)
    kept: List[dict] = []
    for raw_file in raw_files:
        try:
            with open(_long_path(raw_file), "r", encoding="utf-8", errors="replace") as f:
                raw_lines = f.read().splitlines()
        except OSError:
            continue
        for line in raw_lines:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except (ValueError, TypeError):
                kept.append({"_raw": line})
                continue
            try:
                ts_dt = datetime.strptime(str(obj["@timestamp"])[:19], "%Y-%m-%dT%H:%M:%S")
            except (ValueError, TypeError, KeyError):
                kept.append(obj)
                continue
            if lo <= ts_dt <= hi:
                kept.append(obj)
    _write_csv(kept, csv_path)
    for raw_file in raw_files:
        try:
            os.remove(_long_path(raw_file))
        except OSError:
            pass
    return len(kept)


def _winlogbeat_export(ctx: TestContext, out_dir: Path, state: dict, start: datetime, end: datetime) -> None:
    state = state or {}
    raw_files = sorted(out_dir.glob(f"{_WINLOGBEAT_FILE_PREFIX}-*.ndjson"))
    if raw_files:
        kept = _merge_and_trim_winlogbeat_output(raw_files, out_dir / "winlogbeat_output.csv", start, end)
        if kept == 0:
            ctx.note("[WARNING] Winlogbeat ran but no events fell inside this test's time window.")
    else:
        ctx.note("[WARNING] No Winlogbeat output captured for this test.")
    for p in (state.get("yml_path"), state.get("data_dir")):
        if not p:
            continue
        try:
            if Path(p).is_dir():
                shutil.rmtree(p, ignore_errors=True)
            else:
                Path(p).unlink(missing_ok=True)
        except OSError:
            pass


SYSMON = ComparisonTool(
    id="sysmon",
    label="Sysmon",
    folder_name="Sysmon",
    fix_hint="Run setup_comparison_tools.ps1 to install Sysmon.",
    is_available=_sysmon_available,
    begin=_sysmon_begin,
    stop=_sysmon_stop,
    export=_sysmon_export,
)

SILKETW = ComparisonTool(
    id="silketw",
    label="SilkETW",
    folder_name="SilkETW",
    fix_hint="Run setup_comparison_tools.ps1 to install SilkETW.",
    is_available=_silketw_available,
    begin=_silketw_begin,
    stop=_silketw_stop,
    export=_silketw_export,
)

WINLOGBEAT = ComparisonTool(
    id="winlogbeat",
    label="Winlogbeat",
    folder_name="Winlogbeat",
    fix_hint="Run setup_comparison_tools.ps1 to install Winlogbeat.",
    is_available=_winlogbeat_available,
    begin=_winlogbeat_begin,
    stop=_winlogbeat_stop,
    export=_winlogbeat_export,
)

ALL_COMPARISON_TOOLS: List[ComparisonTool] = [SYSMON, SILKETW, WINLOGBEAT]
