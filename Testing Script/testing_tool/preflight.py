from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable, List, Optional, Sequence

from . import comparison_tools, config
from .powershell import is_admin, run_ps


class Status(str, Enum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"


@dataclass
class CheckResult:
    key: str
    name: str
    status: Status
    detail: str
    fix_hint: str = ""
    auto_fix: Optional[Callable[[], "CheckResult"]] = None
    needs_reboot: bool = False
    affects_tests: Sequence[str] = field(default_factory=tuple)


GUI_EXE_PATH: Optional[Path] = None


def find_gui_exe() -> Optional[Path]:
    for directory in config.GUI_EXE_SEARCH_DIRS:
        for name in config.GUI_EXE_CANDIDATES:
            candidate = directory / name
            if candidate.is_file():
                return candidate
    return None


def check_admin() -> CheckResult:
    if is_admin():
        return CheckResult("admin", "Running as Administrator", Status.PASS, "")
    return CheckResult(
        "admin",
        "Running as Administrator",
        Status.FAIL,
        "This script is not running elevated.",
        fix_hint=(
            "Right-click the test runner .exe (or the cmd/PowerShell window) "
            "and choose 'Run as administrator', then start it again. Admin is "
            "required both to read the Security event channel and to run the "
            "PowerShell actions each test performs."
        ),
    )


def check_gui_exe() -> CheckResult:
    global GUI_EXE_PATH
    found = find_gui_exe()
    GUI_EXE_PATH = found
    if found:
        return CheckResult(
            "gui_exe", "EventLogCollector.Gui exe found", Status.PASS, str(found)
        )
    searched = ", ".join(str(d) for d in config.GUI_EXE_SEARCH_DIRS)
    return CheckResult(
        "gui_exe",
        "EventLogCollector.Gui exe found",
        Status.FAIL,
        f"None of {config.GUI_EXE_CANDIDATES} found in: {searched}",
        fix_hint=(
            "Copy 'EventLogCollector.Gui v4.exe' next to this test runner's "
            "exe (or run the test runner from the folder that contains it)."
        ),
    )


def check_powershell() -> CheckResult:
    result = run_ps("$PSVersionTable.PSVersion.Major")
    if result.ok and result.stdout.strip():
        major = result.stdout.strip().splitlines()[-1]
        return CheckResult(
            "powershell", "PowerShell available", Status.PASS, f"Major version {major}"
        )
    return CheckResult(
        "powershell",
        "PowerShell available",
        Status.FAIL,
        "Could not run powershell.exe.",
        fix_hint="powershell.exe must be on PATH  -  this is unusual for a Windows machine.",
    )


def check_disk_space(output_root: Path) -> CheckResult:
    drive = output_root.drive or str(output_root.anchor) or "C:"
    try:
        usage = shutil.disk_usage(drive + "\\" if not drive.endswith("\\") else drive)
    except OSError as exc:
        return CheckResult(
            "disk_space", "Sufficient free disk space", Status.WARN, str(exc)
        )
    free_gb = usage.free / (1024**3)
    if free_gb < 1:
        return CheckResult(
            "disk_space",
            "Sufficient free disk space",
            Status.WARN,
            f"Only {free_gb:.2f} GB free on {drive}.",
            fix_hint="Free up space or point the output folder at a different drive.",
        )
    return CheckResult(
        "disk_space", "Sufficient free disk space", Status.PASS, f"{free_gb:.1f} GB free on {drive}"
    )


def check_channel_enabled(channel: str) -> CheckResult:
    key = f"channel:{channel}"
    result = run_ps(f'(Get-WinEvent -ListLog "{channel}" -ErrorAction Stop).IsEnabled')
    if not result.ok:
        return CheckResult(
            key,
            f"Channel enabled: {channel}",
            Status.WARN,
            "Channel not found on this machine (provider may not be installed)  -  "
            "events from it simply won't appear in either Original or My format.",
        )
    enabled = result.stdout.strip().lower() == "true"
    if enabled:
        return CheckResult(key, f"Channel enabled: {channel}", Status.PASS, "")

    def fix() -> CheckResult:
        run_ps(f'wevtutil sl "{channel}" /e:true', check=True, context=f"enable {channel}")
        return check_channel_enabled(channel)

    return CheckResult(
        key,
        f"Channel enabled: {channel}",
        Status.WARN,
        "Channel exists but is disabled  -  Windows isn't recording to it at all.",
        fix_hint=f'wevtutil sl "{channel}" /e:true',
        auto_fix=fix,
    )


def check_auditpol_subcategory(subcategory: str, affects_tests: Sequence[str]) -> CheckResult:
    key = f"auditpol:{subcategory}"
    result = run_ps(f'auditpol /get /subcategory:"{subcategory}"')
    output = result.stdout
    enabled = result.ok and "success" in output.lower() and "no auditing" not in output.lower()
    if enabled:
        return CheckResult(key, f"Audit policy enabled: {subcategory}", Status.PASS, "")

    def fix() -> CheckResult:
        run_ps(
            f'auditpol /set /subcategory:"{subcategory}" /success:enable',
            check=True,
            context=f"enable auditing for {subcategory}",
        )
        return check_auditpol_subcategory(subcategory, affects_tests)

    return CheckResult(
        key,
        f"Audit policy enabled: {subcategory}",
        Status.WARN,
        f"'{subcategory}' Success auditing is off by default on most Windows installs.",
        fix_hint=f'auditpol /set /subcategory:"{subcategory}" /success:enable',
        auto_fix=fix,
        affects_tests=affects_tests,
    )


def check_registry_dword(
    key_name: str, path: str, value_name: str, expected: int, affects_tests: Sequence[str],
    needs_reboot: bool = False,
) -> CheckResult:
    result = run_ps(
        f'(Get-ItemProperty -Path "{path}" -Name "{value_name}" '
        f'-ErrorAction SilentlyContinue).{value_name}'
    )
    current = result.stdout.strip()
    if result.ok and current == str(expected):
        return CheckResult(key_name, f"Registry set: {value_name}", Status.PASS, "")

    def fix() -> CheckResult:
        run_ps(
            f'New-Item -Path "{path}" -Force | Out-Null; '
            f'New-ItemProperty -Path "{path}" -Name "{value_name}" -Value {expected} '
            f'-PropertyType DWord -Force | Out-Null',
            check=True,
            context=f"set {value_name}",
        )
        return check_registry_dword(key_name, path, value_name, expected, affects_tests, needs_reboot)

    detail = f"Not set (current: {current or 'missing'}, need {expected}) at {path}\\{value_name}"
    return CheckResult(
        key_name,
        f"Registry set: {value_name}",
        Status.WARN,
        detail,
        fix_hint=f'Set DWORD {path}\\{value_name} = {expected}' + (" (reboot required)" if needs_reboot else ""),
        auto_fix=fix,
        needs_reboot=needs_reboot,
        affects_tests=affects_tests,
    )


def check_bitlocker() -> CheckResult:
    result = run_ps(
        "(Get-BitLockerVolume -MountPoint C: -ErrorAction Stop).ProtectionStatus"
    )
    if not result.ok:
        return CheckResult(
            "bitlocker",
            "BitLocker available and on for C:",
            Status.WARN,
            "Get-BitLockerVolume failed  -  BitLocker feature likely unavailable on this "
            "edition/VM.",
            fix_hint="Not auto-fixable. Test 18 (BitLocker modification) will be skipped.",
            affects_tests=["18"],
        )
    on = result.stdout.strip().lower() == "on"
    if on:
        return CheckResult("bitlocker", "BitLocker available and on for C:", Status.PASS, "")
    return CheckResult(
        "bitlocker",
        "BitLocker available and on for C:",
        Status.WARN,
        f"C: protection status is '{result.stdout.strip()}', not On.",
        fix_hint=(
            "Not auto-fixable (enabling encryption takes a long time and isn't safe to "
            "script unattended). Test 18 will be skipped unless C: is already encrypted."
        ),
        affects_tests=["18"],
    )


def check_defender() -> CheckResult:
    result = run_ps("(Get-MpComputerStatus -ErrorAction Stop).AMServiceEnabled")
    if result.ok and result.stdout.strip():
        return CheckResult("defender", "Windows Defender available", Status.PASS, "")
    return CheckResult(
        "defender",
        "Windows Defender available",
        Status.WARN,
        "Get-MpComputerStatus failed  -  Defender may be replaced by third-party AV or "
        "unavailable in this VM.",
        fix_hint="Not auto-fixable. Tests 16, 17, 19, 20 (Defender-related) will be skipped.",
        affects_tests=["16", "17", "19", "20"],
    )


def check_network_adapters() -> CheckResult:
    result = run_ps(
        "(Get-NetAdapter | Where-Object Status -eq 'Up' | Measure-Object).Count"
    )
    count = 0
    if result.ok and result.stdout.strip().isdigit():
        count = int(result.stdout.strip())
    if count >= 2:
        return CheckResult(
            "net_adapters", "Multiple active network adapters", Status.PASS, f"{count} up"
        )
    return CheckResult(
        "net_adapters",
        "Multiple active network adapters",
        Status.WARN,
        f"Only {count} active adapter(s) detected.",
        fix_hint=(
            "Test 4 (connect/disconnect a network) will default to manual/physical mode "
            "for safety  -  disabling this VM's only adapter could cut off remote "
            "access to it."
        ),
        affects_tests=["4"],
    )


def check_comparison_tool(tool: comparison_tools.ComparisonTool) -> CheckResult:
    key = f"comparison_tool:{tool.id}"
    available, detail = tool.is_available()
    if available:
        return CheckResult(key, f"{tool.label} available", Status.PASS, detail)
    return CheckResult(
        key,
        f"{tool.label} available",
        Status.WARN,
        detail,
        fix_hint=tool.fix_hint,
    )


def run_preflight(output_root: Path) -> List[CheckResult]:
    results: List[CheckResult] = [
        check_admin(),
        check_gui_exe(),
        check_powershell(),
        check_disk_space(output_root),
    ]
    for channel in sorted(set(config.WATCHED_CHANNELS) - config.ALWAYS_ON_CHANNELS):
        results.append(check_channel_enabled(channel))

    results.append(check_auditpol_subcategory("Process Creation", affects_tests=["5", "12", "15"]))
    results.append(check_auditpol_subcategory("Removable Storage", affects_tests=["14"]))
    results.append(check_auditpol_subcategory("MPSSVC Rule-Level Policy Change", affects_tests=["1"]))
    results.append(check_auditpol_subcategory("Filtering Platform Policy Change", affects_tests=["1"]))
    results.append(check_auditpol_subcategory("Authorization Policy Change", affects_tests=["3"]))

    results.append(
        check_registry_dword(
            "reg:cmdline_audit",
            r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit",
            "ProcessCreationIncludeCmdLine_Enabled",
            1,
            affects_tests=["5", "12", "15"],
        )
    )
    results.append(
        check_registry_dword(
            "reg:hotplug_secure_open",
            r"HKLM:\SYSTEM\CurrentControlSet\Control\Storage",
            "HotPlugSecureOpen",
            1,
            affects_tests=["14"],
            needs_reboot=True,
        )
    )

    results.append(check_bitlocker())
    results.append(check_defender())
    results.append(check_network_adapters())

    for tool in comparison_tools.ALL_COMPARISON_TOOLS:
        results.append(check_comparison_tool(tool))

    return results


def has_blocking_failures(results: Sequence[CheckResult]) -> bool:
    return any(r.status == Status.FAIL for r in results)
