from __future__ import annotations

import os
import sys
from pathlib import Path

APP_NAME = "EventLogCollector Test Runner"

# artifact prefix
TEST_ARTIFACT_PREFIX = "ELCTest_"


def _base_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


BASE_DIR = _base_dir()

# gui exe candidates
GUI_EXE_CANDIDATES = [
    "EventLogCollector.Gui v4.exe",
    "EventLogCollector.Gui.exe",
]
GUI_EXE_SEARCH_DIRS = [BASE_DIR, Path.cwd()]

DEFAULT_OUTPUT_ROOT = BASE_DIR / "Results"

# buffer between tests
DEFAULT_BUFFER_SECONDS = 40

# settle before stop
DEFAULT_SETTLE_SECONDS = 30

# export window margin
EXPORT_WINDOW_MARGIN_SECONDS = 5

# watched channels
WATCHED_CHANNELS = [
    "System",
    "Security",
    "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
    "Microsoft-Windows-Windows Defender/Operational",
    "Microsoft-Windows-PowerShell/Operational",
    "Microsoft-Windows-TaskScheduler/Operational",
    "Microsoft-Windows-Kernel-PnP/Configuration",
    "Microsoft-Windows-TerminalServices-RDPClient/Operational",
    "Microsoft-Windows-WindowsUpdateClient/Operational",
    "Microsoft-Windows-BitLocker/BitLocker Management",
    "Microsoft-Windows-WindowsBackup/ActionCenter",
    "Microsoft-Windows-NetworkProfile/Operational",
    "Microsoft-Windows-DHCP-Client/Admin",
    "Microsoft-Windows-WLAN-AutoConfig/Operational",
    "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
    "Application",
]

# always-on channels
ALWAYS_ON_CHANNELS = {"System", "Security", "Application"}

# comparison tool paths
SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
SYSMON_SERVICE_NAME = "Sysmon64"
SYSMON_DIR = Path(r"C:\Sysmon")
SYSMON_EXE = SYSMON_DIR / "Sysmon64.exe"

SILKETW_DIR = Path(r"C:\SilkETW")
SILKETW_EXE = SILKETW_DIR / "SilkETW.exe"

WINLOGBEAT_DIR = Path(r"C:\Winlogbeat")
WINLOGBEAT_EXE = WINLOGBEAT_DIR / "winlogbeat.exe"
