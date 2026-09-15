from __future__ import annotations

import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Optional, Sequence

DEFAULT_TIMEOUT_SECONDS = 120


@dataclass
class PsResult:
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


class PowerShellError(RuntimeError):
    def __init__(self, result: PsResult, context: str = ""):
        self.result = result
        message = f"PowerShell command failed (exit {result.returncode})"
        if context:
            message += f" [{context}]"
        if result.stderr.strip():
            message += f":\n{result.stderr.strip()}"
        super().__init__(message)


def run_ps(
    command: str,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
    check: bool = False,
    context: str = "",
) -> PsResult:
    completed = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            command,
        ],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    result = PsResult(completed.returncode, completed.stdout, completed.stderr)
    if check and not result.ok:
        raise PowerShellError(result, context)
    return result


def run_ps_script(
    script_text: str,
    params: Optional[Mapping[str, str]] = None,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
    check: bool = False,
    context: str = "",
) -> PsResult:
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".ps1", delete=False, encoding="utf-8"
    ) as f:
        f.write(script_text)
        script_path = Path(f.name)

    try:
        args = [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script_path),
        ]
        for key, value in (params or {}).items():
            args.append(f"-{key}")
            args.append(value)

        completed = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout
        )
        result = PsResult(completed.returncode, completed.stdout, completed.stderr)
        if check and not result.ok:
            raise PowerShellError(result, context)
        return result
    finally:
        try:
            script_path.unlink(missing_ok=True)
        except OSError:
            pass


def run_diskpart(commands: Sequence[str], timeout: int = 90) -> PsResult:
    script = "\n".join(commands) + "\n"
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False, encoding="utf-8"
    ) as f:
        f.write(script)
        script_path = Path(f.name)
    try:
        completed = subprocess.run(
            ["diskpart", "/s", str(script_path)],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return PsResult(completed.returncode, completed.stdout, completed.stderr)
    finally:
        try:
            script_path.unlink(missing_ok=True)
        except OSError:
            pass


def is_admin() -> bool:
    result = run_ps(
        "([Security.Principal.WindowsPrincipal] "
        "[Security.Principal.WindowsIdentity]::GetCurrent())."
        "IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)"
    )
    return result.ok and result.stdout.strip().lower() == "true"
