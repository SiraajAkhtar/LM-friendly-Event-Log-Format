import re

_ARTIFACT_PREFIX = "ELCTest_"
_SCRATCH_MARKER = "_scratch"


_SEP = r"(?:\\|/|%5C|%2F)"
_HARNESS_PATH_SIGNATURES = [
    re.compile(rf"SilkETW{_SEP}SilkETW\.exe", re.IGNORECASE),
    re.compile(rf"Winlogbeat{_SEP}winlogbeat\.exe", re.IGNORECASE),
    re.compile(r"EventLogCollectorTestRunner\.exe", re.IGNORECASE),
    re.compile(r"EventLogCollector\.Gui\s*v4\.exe", re.IGNORECASE),
]

_TEMP_PS1_SIGNATURE = re.compile(r"tmp[a-z0-9_]+\.ps1", re.IGNORECASE)

_PS_POLICY_TEST_SIGNATURE = re.compile(r"__PSScriptPolicyTest_", re.IGNORECASE)

_HARNESS_PROCESS_NAME_SIGNATURE = re.compile(
    r"ProcessName[:=]\s*(SilkETW|winlogbeat|EventLogCollectorTestRunner|EventLogCollector\.Gui)\b",
    re.IGNORECASE,
)


_PROJECT_PATH_SIGNATURE = re.compile(
    r"Telemetry and Fidelity \(4th Paper\)", re.IGNORECASE
)

_SCRIPTBLOCK_SIGNATURES = [
    re.compile(r"Creating Scriptblock text", re.IGNORECASE),
    re.compile(r"ScriptBlockText=", re.IGNORECASE),
]


def is_noise(row_text: str) -> bool:
    """row_text the full raw text of one log entry (all fields joined) before model prompt."""
    if _ARTIFACT_PREFIX in row_text:
        return True
    if _SCRATCH_MARKER in row_text:
        return True
    if _TEMP_PS1_SIGNATURE.search(row_text):
        return True
    if _PS_POLICY_TEST_SIGNATURE.search(row_text):
        return True
    if _HARNESS_PROCESS_NAME_SIGNATURE.search(row_text):
        return True
    if _PROJECT_PATH_SIGNATURE.search(row_text):
        return True
    for pattern in _HARNESS_PATH_SIGNATURES:
        if pattern.search(row_text):
            return True
    for pattern in _SCRIPTBLOCK_SIGNATURES:
        if pattern.search(row_text):
            return True
    return False
