from __future__ import annotations

import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Sequence

from . import config
from .powershell import PsResult, run_ps_script

_EXPORT_SCRIPT = r"""
param(
    [Parameter(Mandatory=$true)][string]$StartTime,
    [Parameter(Mandatory=$true)][string]$EndTime,
    [Parameter(Mandatory=$true)][string]$OutDir,
    [Parameter(Mandatory=$true)][string]$ChannelsFile
)

$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

# long path support
function Get-LongPath([string]$Path) {
    $full = [System.IO.Path]::GetFullPath($Path)
    if ($full.StartsWith('\\?\')) { return $full }
    if ($full.StartsWith('\\')) { return '\\?\UNC\' + $full.Substring(2) }
    return '\\?\' + $full
}

$styles = [System.Globalization.DateTimeStyles]::RoundtripKind
$culture = [System.Globalization.CultureInfo]::InvariantCulture
$start = [DateTime]::Parse($StartTime, $culture, $styles)
$end   = [DateTime]::Parse($EndTime, $culture, $styles)

$channels = Get-Content -Path $ChannelsFile | Where-Object { $_.Trim() -ne '' }

foreach ($channel in $channels) {
    $safeName = ($channel -replace '[\\/:*?"<>|]', '_')
    $outFile = Get-LongPath (Join-Path $OutDir "$safeName.csv")
    try {
        $events = Get-WinEvent -FilterHashtable @{ LogName = $channel; StartTime = $start; EndTime = $end } -ErrorAction Stop
    } catch {
        $msg = "No events found for channel '$channel' in this window (or the channel is missing/disabled): $($_.Exception.Message)"
        [System.IO.File]::WriteAllText($outFile, $msg + "`r`n", [System.Text.Encoding]::UTF8)
        continue
    }

    $csvLines = $events |
        Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, LogName, TaskDisplayName,
            @{ Name = 'Message'; Expression = { $_.Message } },
            @{ Name = 'Xml'; Expression = { $_.ToXml() } } |
        ConvertTo-Csv -NoTypeInformation
    [System.IO.File]::WriteAllLines($outFile, $csvLines, [System.Text.Encoding]::UTF8)
}

Write-Output "DONE"
"""


def export_original_logs(
    start_utc: datetime,
    end_utc: datetime,
    out_dir: Path,
    channels: Sequence[str] = tuple(config.WATCHED_CHANNELS),
    margin_seconds: int = config.EXPORT_WINDOW_MARGIN_SECONDS,
) -> PsResult:
    out_dir.mkdir(parents=True, exist_ok=True)
    start_margin = start_utc - timedelta(seconds=margin_seconds)
    end_margin = end_utc + timedelta(seconds=margin_seconds)

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False, encoding="utf-8"
    ) as f:
        f.write("\n".join(channels))
        channels_file = Path(f.name)

    try:
        return run_ps_script(
            _EXPORT_SCRIPT,
            params={
                "StartTime": start_margin.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                "EndTime": end_margin.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                "OutDir": str(out_dir),
                "ChannelsFile": str(channels_file),
            },
            timeout=300,
            context="export Original logs",
        )
    finally:
        try:
            channels_file.unlink(missing_ok=True)
        except OSError:
            pass
