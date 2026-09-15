$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

python -m pip install --quiet --upgrade -r requirements.txt

# clear old build
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$PSScriptRoot\build"

python -m PyInstaller `
    --name EventLogCollectorTestRunner `
    --onefile `
    --console `
    --noconfirm `
    run_tests.py

Write-Host ""
Write-Host "Built: $PSScriptRoot\dist\EventLogCollectorTestRunner.exe"
Write-Host "Copy that .exe + 'EventLogCollector.Gui v4.exe' to the test VM (same folder), then run the exe from an elevated cmd/PowerShell there."
