from __future__ import annotations

import csv
import json
import re
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from . import comparison_tools, config
from .context import TestContext, TestSkipped, gen_run_id
from .export_original import export_original_logs
from .powershell import run_ps
from .tests_definitions import TestCase


def sanitize_folder_name(name: str) -> str:
    return re.sub(r'[\\/:*?"<>|]', "_", name).strip()


@dataclass
class TestOutcome:
    id: str
    name: str
    status: str
    kind: str
    start_utc: Optional[str]
    end_utc: Optional[str]
    test_dir: str
    reason: str = ""
    notes: List[str] = field(default_factory=list)


def cleanup_leftover_artifacts(auto_confirm: bool = False) -> None:
    print("\nChecking for leftover test artifacts from a previous interrupted run...")
    prefix = config.TEST_ARTIFACT_PREFIX

    users = run_ps(f"Get-LocalUser | Where-Object Name -like '{prefix}*' | Select-Object -ExpandProperty Name")
    groups = run_ps(f"Get-LocalGroup | Where-Object Name -like '{prefix}*' | Select-Object -ExpandProperty Name")
    exclusions = run_ps(
        f"(Get-MpPreference -ErrorAction SilentlyContinue).ExclusionPath | Where-Object {{ $_ -like '*{prefix}*' }}"
    )

    user_names = [l.strip() for l in users.stdout.splitlines() if l.strip()]
    group_names = [l.strip() for l in groups.stdout.splitlines() if l.strip()]
    exclusion_paths = [l.strip() for l in exclusions.stdout.splitlines() if l.strip()]

    if not (user_names or group_names or exclusion_paths):
        print("  None found.")
        return

    print("  Found leftover artifacts:")
    for u in user_names:
        print(f"    local user:  {u}")
    for g in group_names:
        print(f"    local group: {g}")
    for e in exclusion_paths:
        print(f"    Defender exclusion: {e}")

    if not auto_confirm:
        answer = input("  Remove all of the above now? [Y/n]: ").strip().lower()
        if answer and not answer.startswith("y"):
            print("  Leaving them in place.")
            return

    for u in user_names:
        run_ps(f'Remove-LocalUser -Name "{u}" -ErrorAction SilentlyContinue')
    for g in group_names:
        run_ps(f'Remove-LocalGroup -Name "{g}" -ErrorAction SilentlyContinue')
    for e in exclusion_paths:
        run_ps(f'Remove-MpPreference -ExclusionPath "{e}" -ErrorAction SilentlyContinue')
    print("  Done.")


def _write_manifest(test_dir: Path, outcome: TestOutcome, test: TestCase) -> None:
    manifest = {
        **asdict(outcome),
        "summary": test.summary,
    }
    (test_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    lines = [
        f"Test {outcome.id}: {outcome.name}",
        f"Kind: {outcome.kind}",
        f"Status: {outcome.status}",
        f"Start (UTC): {outcome.start_utc}",
        f"End (UTC): {outcome.end_utc}",
        "",
        f"Summary: {test.summary}",
    ]
    if outcome.reason:
        lines += ["", f"Reason: {outcome.reason}"]
    lines += ["", "Notes:"]
    lines += [f"  {n}" for n in outcome.notes] or ["  (none)"]
    (test_dir / "manifest.txt").write_text("\n".join(lines), encoding="utf-8")


def run_tests(
    tests: List[TestCase],
    output_root: Path,
    buffer_seconds: int = config.DEFAULT_BUFFER_SECONDS,
    settle_seconds: int = config.DEFAULT_SETTLE_SECONDS,
    auto_confirm: bool = False,
) -> Path:
    run_id = gen_run_id()
    run_dir = output_root / run_id
    scratch_dir = run_dir / "_scratch"
    scratch_dir.mkdir(parents=True, exist_ok=True)

    outcomes: List[TestOutcome] = []

    print(f"\n=== Run {run_id}  -  {len(tests)} test(s)  -  output: {run_dir} ===\n")

    available_tools: List[comparison_tools.ComparisonTool] = []
    for tool in comparison_tools.ALL_COMPARISON_TOOLS:
        ok, detail = tool.is_available()
        print(f"  comparison tool {tool.label}: {'capturing' if ok else 'SKIPPED'} ({detail})")
        if ok:
            available_tools.append(tool)

    for i, test in enumerate(tests):
        test_dir = run_dir / f"{test.id} - {sanitize_folder_name(test.name)}"
        original_dir = test_dir / "Original"
        myformat_dir = test_dir / "My format"
        original_dir.mkdir(parents=True, exist_ok=True)
        myformat_dir.mkdir(parents=True, exist_ok=True)

        tool_dirs = {}
        for tool in comparison_tools.ALL_COMPARISON_TOOLS:
            tool_dir = test_dir / tool.folder_name
            tool_dir.mkdir(parents=True, exist_ok=True)
            tool_dirs[tool.id] = tool_dir
            if tool not in available_tools:
                (tool_dir / "NOT_CAPTURED.txt").write_text(
                    f"{tool.label} was not available on this machine for this run "
                    "(see the preflight report) -- no capture attempted.\n",
                    encoding="utf-8",
                )

        ctx = TestContext(test_id=test.id, scratch_dir=scratch_dir, auto_confirm=auto_confirm)
        ctx.state["run_id"] = run_id

        print(f"\n{'=' * 70}\nTest {test.id}/{len(tests):02d}: {test.name}  [{test.kind}]\n{test.summary}\n{'=' * 70}")

        outcome = TestOutcome(
            id=test.id, name=test.name, status="PASS", kind=test.kind,
            start_utc=None, end_utc=None, test_dir=str(test_dir),
        )

        if test.precheck:
            try:
                reason = test.precheck(ctx)
            except Exception as exc:  # noqa: BLE001
                reason = f"precheck raised an error: {exc}"
            if reason:
                outcome.status = "SKIPPED"
                outcome.reason = reason
                outcome.notes = ctx.notes
                ctx.note(f"[SKIPPED] {reason}")
                _write_manifest(test_dir, outcome, test)
                outcomes.append(outcome)
                print(f"Skipped: {reason}")
                continue

        if test.setup:
            try:
                test.setup(ctx)
            except Exception as exc:  # noqa: BLE001
                ctx.note(f"[ERROR] setup failed: {exc}")
                outcome.status = "ERROR"

        print(
            f"\n>>> In EventLogCollector.Gui: set 'Save logs to' to:\n    {myformat_dir}\n"
            f">>> Then click Start Recording."
        )
        ctx.prompt_enter("Confirm recording has started")
        start_time = datetime.now(timezone.utc)
        outcome.start_utc = start_time.isoformat()

        tool_states: dict = {}
        for tool in available_tools:
            try:
                tool_states[tool.id] = tool.begin(ctx, tool_dirs[tool.id])
            except Exception as exc:  # noqa: BLE001
                ctx.note(f"[WARNING] {tool.label} capture failed to start: {exc}")

        try:
            test.action(ctx)
        except TestSkipped as skip:
            outcome.status = "SKIPPED"
            outcome.reason = str(skip)
        except Exception as exc:  # noqa: BLE001
            ctx.note(f"[ERROR] action failed: {exc}")
            outcome.status = "ERROR"

        ctx.note(f"Settling for {settle_seconds}s before stopping recording...")
        time.sleep(settle_seconds)

        ctx.prompt_enter("Click Stop Recording in the GUI now, then confirm here")
        end_time = datetime.now(timezone.utc)
        outcome.end_utc = end_time.isoformat()

        for tool in available_tools:
            try:
                tool.stop(ctx, tool_states.get(tool.id))
            except Exception as exc:  # noqa: BLE001
                ctx.note(f"[WARNING] {tool.label} capture failed to stop cleanly: {exc}")

        if test.revert:
            try:
                test.revert(ctx)
            except Exception as exc:  # noqa: BLE001
                ctx.note(f"[ERROR] revert failed  -  this test's change may need to be undone by hand: {exc}")
                outcome.status = "ERROR"

        try:
            export_original_logs(start_time, end_time, original_dir)
        except Exception as exc:  # noqa: BLE001
            ctx.note(f"[ERROR] Original log export failed: {exc}")
            outcome.status = "ERROR"

        for tool in available_tools:
            try:
                tool.export(ctx, tool_dirs[tool.id], tool_states.get(tool.id), start_time, end_time)
            except Exception as exc:  # noqa: BLE001
                ctx.note(f"[WARNING] {tool.label} export/finalize failed: {exc}")

        my_format_files = list(myformat_dir.glob("*.csv"))
        if not my_format_files:
            ctx.note(
                "[WARNING] No .csv found in 'My format'  -  check the GUI was pointed at the "
                "right folder and Start/Stop Recording were both clicked."
            )
            if outcome.status == "PASS":
                outcome.status = "ERROR"

        outcome.notes = ctx.notes
        _write_manifest(test_dir, outcome, test)
        outcomes.append(outcome)

        is_last = i == len(tests) - 1
        if not is_last:
            print(f"\nBuffering {buffer_seconds}s before the next test...")
            time.sleep(buffer_seconds)

    _write_run_summary(run_dir, outcomes)
    print(f"\n=== Run complete: {run_dir} ===")
    return run_dir


def _write_run_summary(run_dir: Path, outcomes: List[TestOutcome]) -> None:
    csv_path = run_dir / "summary.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["ID", "Name", "Status", "Kind", "Start (UTC)", "End (UTC)", "Folder", "Reason"])
        for o in outcomes:
            writer.writerow([o.id, o.name, o.status, o.kind, o.start_utc, o.end_utc, o.test_dir, o.reason])
    (run_dir / "summary.json").write_text(
        json.dumps([asdict(o) for o in outcomes], indent=2), encoding="utf-8"
    )
