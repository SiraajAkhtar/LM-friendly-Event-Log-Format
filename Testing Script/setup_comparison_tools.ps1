$ErrorActionPreference = "Stop"

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run elevated (Administrator) - Sysmon's driver install needs it."
    exit 1
}

$sysmonDir     = "C:\Sysmon"
$silketwDir    = "C:\SilkETW"
$winlogbeatDir = "C:\Winlogbeat"
$tempDir       = Join-Path $env:TEMP "elc_comparison_tools_setup"
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

function Get-File($Url, $OutFile) {
    Write-Host "  Downloading $Url"
    Invoke-WebRequest -Uri $Url -OutFile $OutFile -UseBasicParsing
}

Write-Host "`n=== Sysmon ==="
if (Get-Service -Name Sysmon64 -ErrorAction SilentlyContinue) {
    Write-Host "  Already installed (service Sysmon64 present) - skipping."
} else {
    New-Item -ItemType Directory -Path $sysmonDir -Force | Out-Null
    $sysmonZip = Join-Path $tempDir "Sysmon.zip"
    Get-File "https://download.sysinternals.com/files/Sysmon.zip" $sysmonZip
    Expand-Archive -Path $sysmonZip -DestinationPath $sysmonDir -Force

    $configPath = Join-Path $sysmonDir "sysmonconfig.xml"
    Get-File "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" $configPath

    Write-Host "  Installing Sysmon driver + service..."
    & "$sysmonDir\Sysmon64.exe" -accepteula -i $configPath
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Sysmon install failed (exit $LASTEXITCODE)."
        exit 1
    }
    Write-Host "  Installed."
}

Write-Host "`n=== SilkETW ==="
if (Test-Path (Join-Path $silketwDir "SilkETW.exe")) {
    Write-Host "  Already present at $silketwDir - skipping."
} else {
    New-Item -ItemType Directory -Path $silketwDir -Force | Out-Null
    $silketwZip = Join-Path $tempDir "SilkETW.zip"
    Get-File "https://github.com/mandiant/SilkETW/releases/download/v0.8/SilkETW_SilkService_v8.zip" $silketwZip
    $silketwExtract = Join-Path $tempDir "SilkETW_extract"
    Expand-Archive -Path $silketwZip -DestinationPath $silketwExtract -Force

    $silketwExe = Get-ChildItem -Path $silketwExtract -Filter "SilkETW.exe" -Recurse | Select-Object -First 1
    if (-not $silketwExe) {
        Write-Error "SilkETW.exe not found inside the downloaded archive."
        exit 1
    }
    Copy-Item -Path (Join-Path $silketwExe.DirectoryName "*") -Destination $silketwDir -Recurse -Force
    Write-Host "  Installed to $silketwDir."
}

Write-Host "`n=== Winlogbeat ==="
if (Test-Path (Join-Path $winlogbeatDir "winlogbeat.exe")) {
    Write-Host "  Already present at $winlogbeatDir - skipping."
} else {
    New-Item -ItemType Directory -Path $winlogbeatDir -Force | Out-Null
    $winlogbeatZip = Join-Path $tempDir "winlogbeat.zip"
    Get-File "https://artifacts.elastic.co/downloads/beats/winlogbeat/winlogbeat-9.5.1-windows-x86_64.zip" $winlogbeatZip
    $winlogbeatExtract = Join-Path $tempDir "winlogbeat_extract"
    Expand-Archive -Path $winlogbeatZip -DestinationPath $winlogbeatExtract -Force

    $winlogbeatExe = Get-ChildItem -Path $winlogbeatExtract -Filter "winlogbeat.exe" -Recurse | Select-Object -First 1
    if (-not $winlogbeatExe) {
        Write-Error "winlogbeat.exe not found inside the downloaded archive."
        exit 1
    }
    Copy-Item -Path (Join-Path $winlogbeatExe.DirectoryName "*") -Destination $winlogbeatDir -Recurse -Force
    Write-Host "  Installed to $winlogbeatDir."
}

Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $tempDir

Write-Host "`nDone. Re-run this test runner's preflight check to confirm all three now show PASS."
