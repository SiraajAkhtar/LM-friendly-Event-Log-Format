from __future__ import annotations

import secrets
import string
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import List

from .powershell import PsResult, run_ps, run_ps_script


def gen_run_id() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def gen_test_password() -> str:
    body = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(10))
    return f"Elc!{body}9Aa"


@dataclass
class TestContext:
    test_id: str
    scratch_dir: Path
    notes: List[str] = field(default_factory=list)
    state: dict = field(default_factory=dict)
    auto_confirm: bool = False

    def note(self, text: str) -> None:
        stamped = f"[{datetime.now().strftime('%H:%M:%S')}] {text}"
        self.notes.append(stamped)
        print(stamped)

    def run(self, command: str, context: str = "") -> PsResult:
        result = run_ps(command, context=context or self.test_id)
        summary = (
            f"$ {command}\n"
            f"  exit={result.returncode}"
            + (f" stdout={result.stdout.strip()!r}" if result.stdout.strip() else "")
            + (f" stderr={result.stderr.strip()!r}" if result.stderr.strip() else "")
        )
        self.note(summary)
        return result

    def run_script(self, script_text: str, params: dict | None = None, context: str = "") -> PsResult:
        result = run_ps_script(script_text, params=params, context=context or self.test_id)
        summary = (
            f"$ <script block>\n"
            f"  exit={result.returncode}"
            + (f" stdout={result.stdout.strip()!r}" if result.stdout.strip() else "")
            + (f" stderr={result.stderr.strip()!r}" if result.stderr.strip() else "")
        )
        self.note(summary)
        return result

    def prompt_enter(self, message: str) -> None:
        self.note(f"[MANUAL STEP] {message}")
        if self.auto_confirm:
            self.note("[MANUAL STEP] auto-confirmed (non-interactive mode)")
            return
        input(f"\n    >>> {message}\n    Press Enter once done... ")

    def confirm(self, message: str, default: bool = False) -> bool:
        if self.auto_confirm:
            self.note(f"[CONFIRM] '{message}' -> auto-default ({default})")
            return default
        suffix = "[Y/n]" if default else "[y/N]"
        answer = input(f"    {message} {suffix}: ").strip().lower()
        if not answer:
            return default
        return answer.startswith("y")

    def skip(self, reason: str) -> None:
        self.note(f"[SKIPPED] {reason}")
        raise TestSkipped(reason)


class TestSkipped(Exception):
    pass
