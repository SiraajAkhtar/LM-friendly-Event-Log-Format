from __future__ import annotations

import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional

from . import config
from .context import TestContext, gen_test_password
from .powershell import run_diskpart


@dataclass
class TestCase:
    id: str
    name: str
    kind: str
    summary: str
    action: Callable[[TestContext], None]
    setup: Optional[Callable[[TestContext], None]] = None
    revert: Optional[Callable[[TestContext], None]] = None
    precheck: Optional[Callable[[TestContext], Optional[str]]] = None


def artifact_name(base: str, ctx: TestContext) -> str:
    return f"{config.TEST_ARTIFACT_PREFIX}{base}_{ctx.state.get('run_id', '')}"


def artifact_account_name(base: str, ctx: TestContext) -> str:
    run_id = str(ctx.state.get("run_id", ""))
    suffix = run_id[-6:] if run_id else secrets.token_hex(3)
    name = f"{config.TEST_ARTIFACT_PREFIX}{base}{suffix}"
    if len(name) > 20:
        raise ValueError(f"account/group name {name!r} exceeds Windows' 20-char SAM limit -- shorten base {base!r}")
    return name


# firewall
def action_firewall(ctx: TestContext) -> None:
    ctx.run("Set-NetFirewallProfile -All -Enabled False", context="disable firewall")


def revert_firewall(ctx: TestContext) -> None:
    ctx.run("Set-NetFirewallProfile -All -Enabled True", context="re-enable firewall")


# password
def setup_password(ctx: TestContext) -> None:
    user = artifact_account_name("Pw", ctx)
    pw1 = gen_test_password()
    ctx.state["pw_user"] = user
    ctx.run(
        f'$sec = ConvertTo-SecureString "{pw1}" -AsPlainText -Force; '
        f'New-LocalUser -Name "{user}" -Password $sec -FullName "ELC Test Password Account" '
        f'-Description "ELCTest temp account - safe to delete" '
        f"-AccountNeverExpires -PasswordNeverExpires",
        context="create temp password-test account",
    )


def action_password(ctx: TestContext) -> None:
    user = ctx.state["pw_user"]
    pw2 = gen_test_password()
    ctx.run(
        f'$sec = ConvertTo-SecureString "{pw2}" -AsPlainText -Force; '
        f'Set-LocalUser -Name "{user}" -Password $sec',
        context="reset temp account password",
    )
    ctx.note(
        "Note: this is an admin-driven reset (Security 4724), not a self-service change "
        "(4723)  -  a genuine self-change needs an interactive logon as the test account, "
        "which this script doesn't attempt. Both are curated by the tool under test."
    )


def revert_password(ctx: TestContext) -> None:
    user = ctx.state.get("pw_user")
    if user:
        ctx.run(f'Remove-LocalUser -Name "{user}" -ErrorAction SilentlyContinue', context="delete temp account")


# permissions
def setup_permissions(ctx: TestContext) -> None:
    user = artifact_account_name("PermU", ctx)
    group = artifact_account_name("PermG", ctx)
    pw = gen_test_password()
    ctx.state["perm_user"] = user
    ctx.state["perm_group"] = group
    ctx.run(
        f'$sec = ConvertTo-SecureString "{pw}" -AsPlainText -Force; '
        f'New-LocalUser -Name "{user}" -Password $sec -FullName "ELC Test Permissions Account" '
        f'-Description "ELCTest temp account - safe to delete" '
        f"-AccountNeverExpires -PasswordNeverExpires",
        context="create temp permissions-test account",
    )
    ctx.run(
        f'New-LocalGroup -Name "{group}" -Description "ELCTest temp group - safe to delete"',
        context="create temp permissions-test group",
    )


def action_permissions(ctx: TestContext) -> None:
    user, group = ctx.state["perm_user"], ctx.state["perm_group"]
    ctx.run(f'Add-LocalGroupMember -Group "{group}" -Member "{user}"', context="add group member")
    time.sleep(2)
    ctx.run(f'Remove-LocalGroupMember -Group "{group}" -Member "{user}"', context="remove group member")


def revert_permissions(ctx: TestContext) -> None:
    user, group = ctx.state.get("perm_user"), ctx.state.get("perm_group")
    if group:
        ctx.run(f'Remove-LocalGroup -Name "{group}" -ErrorAction SilentlyContinue', context="delete temp group")
    if user:
        ctx.run(f'Remove-LocalUser -Name "{user}" -ErrorAction SilentlyContinue', context="delete temp account")


# network
def action_network(ctx: TestContext) -> None:
    r = ctx.run("(Get-NetAdapter | Where-Object Status -eq 'Up' | Measure-Object).Count")
    count = int(r.stdout.strip()) if r.stdout.strip().isdigit() else 0
    auto = False
    if count >= 2:
        auto = ctx.confirm(
            "Multiple active network adapters detected. Auto toggle a NON-primary adapter "
            "off/on automatically instead of doing it by hand?",
            default=False,
        )
    if auto:
        r2 = ctx.run(
            "Get-NetAdapter | Where-Object Status -eq 'Up' | "
            "Sort-Object -Property ifIndex | Select-Object -Skip 1 -First 1 -ExpandProperty Name"
        )
        adapter = r2.stdout.strip()
        if not adapter:
            ctx.note("Could not identify a safe secondary adapter  -  falling back to manual mode.")
            auto = False
        else:
            ctx.state["network_adapter"] = adapter
            ctx.run(f'Disable-NetAdapter -Name "{adapter}" -Confirm:$false', context="disable adapter")
            time.sleep(3)
            ctx.run(f'Enable-NetAdapter -Name "{adapter}" -Confirm:$false', context="enable adapter")
    if not auto:
        ctx.prompt_enter(
            "Disconnect this machine's network (unplug the cable, or turn Wi-Fi off) now, "
            "wait a few seconds, then reconnect it. IMPORTANT: if this VM is only reachable "
            "over this same connection, confirm reconnection is possible before doing this."
        )


# launch app
def action_launch_app(ctx: TestContext) -> None:
    ctx.run("Start-Process notepad.exe", context="launch notepad")
    time.sleep(3)
    ctx.run('Stop-Process -Name notepad -Force -ErrorAction SilentlyContinue', context="close notepad")


# crash
_CRASH_SRC = (
    'class Program { static void Main() { throw new System.Exception('
    '"ELCTest deliberate crash for WER testing"); } }'
)


def action_crash(ctx: TestContext) -> None:
    exe_path = ctx.scratch_dir / f"{artifact_name('CrashApp', ctx)}.exe"
    ctx.state["crash_exe"] = str(exe_path)
    script = (
        "$src = @'\n" + _CRASH_SRC + "\n'@\n"
        f'Add-Type -TypeDefinition $src -Language CSharp -OutputAssembly "{exe_path}" '
        "-OutputType ConsoleApplication\n"
        f'Start-Process -FilePath "{exe_path}"\n'
    )
    ctx.run_script(script, context="compile + run crash test app")
    ctx.note(
        "A 'has stopped working' dialog may appear on screen  -  that's expected (WER "
        "handling the crash) and will be closed automatically during revert."
    )
    time.sleep(4)


def revert_crash(ctx: TestContext) -> None:
    exe_path = ctx.state.get("crash_exe")
    ctx.run('Stop-Process -Name WerFault -Force -ErrorAction SilentlyContinue', context="close WER dialog")
    if exe_path:
        stem = Path(exe_path).stem
        ctx.run(f'Stop-Process -Name "{stem}" -Force -ErrorAction SilentlyContinue', context="stop crash app")
        ctx.run(f'Remove-Item -Path "{exe_path}" -Force -ErrorAction SilentlyContinue', context="delete crash exe")


# external storage
def action_external_storage(ctx: TestContext) -> None:
    physical = ctx.confirm(
        "Is a real USB/external storage device available to plug in for this test?",
        default=True,
    )
    ctx.state["storage_physical"] = physical
    if physical:
        ctx.prompt_enter(
            "Plug in the external storage device now and wait a few seconds for Windows "
            "to finish detecting it."
        )
    else:
        ctx.note(
            "No physical device offered  -  simulating via a temporary VHD attach (generic "
            "Kernel-PnP/volume events only, not USBSTOR-class  -  a known limitation, not "
            "equivalent to a real device)."
        )
        vhd = ctx.scratch_dir / f"{artifact_name('Storage', ctx)}.vhd"
        ctx.state["storage_vhd"] = str(vhd)
        result = run_diskpart(
            [
                f'create vdisk file="{vhd}" maximum=64',
                f'select vdisk file="{vhd}"',
                "attach vdisk",
                "create partition primary",
                'format fs=ntfs quick label="ELCTest"',
                "assign letter=X",
            ]
        )
        ctx.note(f"diskpart attach: exit={result.returncode}\n{result.stdout.strip()[-500:]}")


def revert_external_storage(ctx: TestContext) -> None:
    if ctx.state.get("storage_physical"):
        ctx.prompt_enter("Safely eject/unplug the external storage device now.")
        return
    vhd = ctx.state.get("storage_vhd")
    if vhd:
        result = run_diskpart([f'select vdisk file="{vhd}"', "detach vdisk"])
        ctx.note(f"diskpart detach: exit={result.returncode}")
        try:
            Path(vhd).unlink(missing_ok=True)
        except OSError:
            pass


# windows update
_WU_KEY = r"HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings"


def setup_windows_update(ctx: TestContext) -> None:
    r = ctx.run(
        f'(Get-ItemProperty -Path "{_WU_KEY}" -Name ActiveHoursStart -ErrorAction SilentlyContinue).ActiveHoursStart'
    )
    ctx.state["wu_original"] = r.stdout.strip() or None


def action_windows_update(ctx: TestContext) -> None:
    original = ctx.state.get("wu_original")
    base = int(original) if original and original.isdigit() else 8
    new_value = (base + 1) % 24
    ctx.state["wu_new"] = new_value
    ctx.run(
        f'New-Item -Path "{_WU_KEY}" -Force | Out-Null; '
        f'Set-ItemProperty -Path "{_WU_KEY}" -Name ActiveHoursStart -Value {new_value} -Type DWord',
        context="change Windows Update active hours",
    )


def revert_windows_update(ctx: TestContext) -> None:
    original = ctx.state.get("wu_original")
    if original:
        ctx.run(
            f'Set-ItemProperty -Path "{_WU_KEY}" -Name ActiveHoursStart -Value {original} -Type DWord',
            context="restore Windows Update active hours",
        )
    else:
        ctx.run(
            f'Remove-ItemProperty -Path "{_WU_KEY}" -Name ActiveHoursStart -ErrorAction SilentlyContinue',
            context="remove Windows Update active hours override",
        )


# backup config
def action_backup_config(ctx: TestContext) -> None:
    ctx.note(
        "No safe scriptable path was found for Windows Backup app configuration (needs a "
        "Microsoft-account-signed-in session)  -  manual only."
    )
    ctx.prompt_enter(
        "Open Settings > Accounts > Windows Backup (or Update & Security > Backup on older "
        "builds) and toggle one backup option (e.g. a folder sync toggle)."
    )


def revert_backup_config(ctx: TestContext) -> None:
    ctx.prompt_enter("Revert the backup option just changed back to its original state, then close Settings.")


# timezone
def setup_timezone(ctx: TestContext) -> None:
    r = ctx.run("tzutil /g")
    ctx.state["tz_original"] = r.stdout.strip()


def action_timezone(ctx: TestContext) -> None:
    original = ctx.state.get("tz_original") or "GMT Standard Time"
    target = "Pacific Standard Time" if original != "Pacific Standard Time" else "GMT Standard Time"
    ctx.state["tz_target"] = target
    ctx.run(f'tzutil /s "{target}"', context="change time zone")


def revert_timezone(ctx: TestContext) -> None:
    original = ctx.state.get("tz_original")
    if original:
        ctx.run(f'tzutil /s "{original}"', context="restore time zone")


# screen share
def precheck_screen(ctx: TestContext) -> Optional[str]:
    has_display = ctx.confirm(
        "Is a second display/projector available to physically or wirelessly connect "
        "for this test?",
        default=False,
    )
    if not has_display:
        return (
            "No second display/projector available. Interpreted (per project notes) as "
            "physically/wirelessly connecting an external display, believed covered by the "
            "generic Kernel-PnP device-connect events but not independently verified."
        )
    return None


def action_screen(ctx: TestContext) -> None:
    ctx.prompt_enter("Connect the external display/projector now (HDMI/wireless) and wait for Windows to detect it.")


def revert_screen(ctx: TestContext) -> None:
    ctx.prompt_enter("Disconnect the external display/projector now.")


# admin app
def action_admin_app(ctx: TestContext) -> None:
    ctx.run("Start-Process notepad.exe -Verb RunAs", context="launch notepad elevated")
    time.sleep(3)
    ctx.run('Stop-Process -Name notepad -Force -ErrorAction SilentlyContinue', context="close notepad")


# screenshot
_SCREENSHOT_SCRIPT = r"""
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
$bounds = [System.Windows.Forms.SystemInformation]::VirtualScreen
$bmp = New-Object System.Drawing.Bitmap $bounds.Width, $bounds.Height
$graphics = [System.Drawing.Graphics]::FromImage($bmp)
$graphics.CopyFromScreen($bounds.Location, [System.Drawing.Point]::Empty, $bounds.Size)
$picturesPath = [Environment]::GetFolderPath('MyPictures')
$dir = Join-Path $picturesPath 'Screenshots'
New-Item -ItemType Directory -Path $dir -Force | Out-Null
$name = "Screenshot " + (Get-Date -Format 'yyyy-MM-dd HHmmss') + ".png"
$path = Join-Path $dir $name
$bmp.Save($path, [System.Drawing.Imaging.ImageFormat]::Png)
$graphics.Dispose()
$bmp.Dispose()
Write-Output $path
"""


def action_screenshot(ctx: TestContext) -> None:
    r = ctx.run_script(_SCREENSHOT_SCRIPT, context="capture screenshot")
    path = r.stdout.strip().splitlines()[-1] if r.stdout.strip() else ""
    if path:
        ctx.state["screenshot_path"] = path


def revert_screenshot(ctx: TestContext) -> None:
    path = ctx.state.get("screenshot_path")
    if path:
        ctx.run(f'Remove-Item -Path "{path}" -Force -ErrorAction SilentlyContinue', context="delete test screenshot")


# data export
def action_data_export(ctx: TestContext) -> None:
    test_file = ctx.scratch_dir / f"{artifact_name('ExportFile', ctx)}.txt"
    test_file.write_text("ELCTest sample data for the external-export test.\n", encoding="utf-8")
    ctx.state["export_source"] = str(test_file)
    physical = ctx.confirm(
        "Is a real USB/external drive attached to copy a test file onto?", default=True
    )
    ctx.state["export_physical"] = physical
    if physical:
        ctx.prompt_enter(f"Copy the test file at {test_file} onto the external/USB drive now.")
    else:
        ctx.note(
            "No physical device offered  -  simulating via a temporary VHD (copies the test "
            "file onto an attached virtual disk)."
        )
        vhd = ctx.scratch_dir / f"{artifact_name('ExportVhd', ctx)}.vhd"
        ctx.state["export_vhd"] = str(vhd)
        run_diskpart(
            [
                f'create vdisk file="{vhd}" maximum=64',
                f'select vdisk file="{vhd}"',
                "attach vdisk",
                "create partition primary",
                'format fs=ntfs quick label="ELCTest"',
                "assign letter=Y",
            ]
        )
        ctx.run(f'Copy-Item -Path "{test_file}" -Destination "Y:\\" -Force', context="copy test file to VHD")


def revert_data_export(ctx: TestContext) -> None:
    if ctx.state.get("export_physical"):
        ctx.prompt_enter("Delete the copied test file from the USB/external drive, then safely eject it.")
    else:
        vhd = ctx.state.get("export_vhd")
        if vhd:
            result = run_diskpart([f'select vdisk file="{vhd}"', "detach vdisk"])
            ctx.note(f"diskpart detach: exit={result.returncode}")
            try:
                Path(vhd).unlink(missing_ok=True)
            except OSError:
                pass
    source = ctx.state.get("export_source")
    if source:
        try:
            Path(source).unlink(missing_ok=True)
        except OSError:
            pass


# unauthorised access
def setup_unauthorised(ctx: TestContext) -> None:
    user = artifact_account_name("Admin", ctx)
    pw = gen_test_password()
    ctx.state["unauth_user"] = user
    ctx.run(
        f'$sec = ConvertTo-SecureString "{pw}" -AsPlainText -Force; '
        f'New-LocalUser -Name "{user}" -Password $sec -FullName "ELC Test Admin Account" '
        f'-Description "ELCTest temp account - safe to delete" '
        f"-AccountNeverExpires -PasswordNeverExpires; "
        f'Add-LocalGroupMember -Group "Administrators" -Member "{user}"',
        context="create temp admin-group test account",
    )


def action_unauthorised(ctx: TestContext) -> None:
    user = ctx.state["unauth_user"]
    wrong_pw = "Wr0ng-Password!NotReal"
    ctx.run(
        f'$sec = ConvertTo-SecureString "{wrong_pw}" -AsPlainText -Force; '
        f'$cred = New-Object System.Management.Automation.PSCredential(".\\{user}", $sec); '
        f'Start-Process -FilePath "cmd.exe" -ArgumentList "/c exit" -Credential $cred -ErrorAction SilentlyContinue',
        context="deliberate wrong-password elevation attempt",
    )


def revert_unauthorised(ctx: TestContext) -> None:
    user = ctx.state.get("unauth_user")
    if user:
        ctx.run(f'Remove-LocalUser -Name "{user}" -ErrorAction SilentlyContinue', context="delete temp admin account")


# allow list
def precheck_defender(ctx: TestContext) -> Optional[str]:
    r = ctx.run("(Get-MpComputerStatus -ErrorAction SilentlyContinue).AMServiceEnabled")
    if not r.ok or not r.stdout.strip():
        return "Windows Defender not available (Get-MpComputerStatus failed)  -  third-party AV or unsupported VM."
    return None


def action_allowlist(ctx: TestContext) -> None:
    path = str(ctx.scratch_dir / artifact_name("AllowPath", ctx))
    ctx.state["allow_path"] = path
    ctx.run(
        f'New-Item -ItemType Directory -Path "{path}" -Force | Out-Null; Add-MpPreference -ExclusionPath "{path}"',
        context="add Defender exclusion",
    )


def revert_allowlist(ctx: TestContext) -> None:
    path = ctx.state.get("allow_path")
    if path:
        ctx.run(f'Remove-MpPreference -ExclusionPath "{path}" -ErrorAction SilentlyContinue', context="remove Defender exclusion")


# block list
def setup_blocklist(ctx: TestContext) -> None:
    path = str(ctx.scratch_dir / artifact_name("BlockPath", ctx))
    ctx.state["block_path"] = path
    ctx.run(
        f'New-Item -ItemType Directory -Path "{path}" -Force | Out-Null; Add-MpPreference -ExclusionPath "{path}"',
        context="pre-add Defender exclusion (arranged, not part of the timed test)",
    )


def action_blocklist(ctx: TestContext) -> None:
    path = ctx.state.get("block_path")
    ctx.run(f'Remove-MpPreference -ExclusionPath "{path}" -ErrorAction SilentlyContinue', context="remove Defender exclusion")


# bitlocker
def precheck_bitlocker(ctx: TestContext) -> Optional[str]:
    r = ctx.run('(Get-BitLockerVolume -MountPoint C: -ErrorAction SilentlyContinue).ProtectionStatus')
    if r.stdout.strip().lower() != "on":
        return (
            f"C: BitLocker protection status is '{r.stdout.strip() or 'unavailable'}', not On  -  "
            "can't safely test suspend/resume without BitLocker already protecting the volume."
        )
    return None


def action_bitlocker(ctx: TestContext) -> None:
    ctx.run("Suspend-BitLocker -MountPoint C: -RebootCount 0", context="suspend BitLocker")
    time.sleep(5)
    ctx.run("Resume-BitLocker -MountPoint C:", context="resume BitLocker")


# realtime protection
def action_realtime_protection(ctx: TestContext) -> None:
    ctx.run("Set-MpPreference -DisableRealtimeMonitoring $true", context="disable real-time protection")
    time.sleep(5)
    ctx.run("Set-MpPreference -DisableRealtimeMonitoring $false", context="re-enable real-time protection")
    check = ctx.run("(Get-MpComputerStatus).RealTimeProtectionEnabled")
    if check.stdout.strip().lower() != "true":
        ctx.note("WARNING: real-time protection did not report enabled after re-enabling  -  retrying.")
        ctx.run("Set-MpPreference -DisableRealtimeMonitoring $false", context="retry re-enable real-time protection")


# defender settings
def setup_defender_settings(ctx: TestContext) -> None:
    r = ctx.run("(Get-MpPreference).PUAProtection")
    ctx.state["pua_original"] = r.stdout.strip()


def action_defender_settings(ctx: TestContext) -> None:
    original = ctx.state.get("pua_original")
    new_value = "0" if original == "1" else "1"
    ctx.state["pua_new"] = new_value
    ctx.run(f"Set-MpPreference -PUAProtection {new_value}", context="change PUA protection setting")


def revert_defender_settings(ctx: TestContext) -> None:
    original = ctx.state.get("pua_original")
    if original:
        ctx.run(f"Set-MpPreference -PUAProtection {original}", context="restore PUA protection setting")


ALL_TESTS: List[TestCase] = [
    TestCase("01", "Turning off firewall", "auto",
             "Disables then re-enables all Windows Firewall profiles.",
             action_firewall, revert=revert_firewall),
    TestCase("02", "Changing password", "auto",
             "Creates a temp local account and resets its password (admin-driven reset).",
             action_password, setup=setup_password, revert=revert_password),
    TestCase("03", "Changing the permissions of an account", "auto",
             "Creates a temp account+group, adds then removes group membership.",
             action_permissions, setup=setup_permissions, revert=revert_permissions),
    TestCase("04", "Connecting and disconnecting a network", "hybrid",
             "Toggles a secondary network adapter, or prompts for it to be done manually.",
             action_network),
    TestCase("05", "Launching an application", "auto",
             "Starts and closes Notepad.",
             action_launch_app),
    TestCase("06", "An application crashing", "auto",
             "Compiles and runs a throwaway app that throws an unhandled exception.",
             action_crash, revert=revert_crash),
    TestCase("07", "Connecting an external storage device", "hybrid",
             "Prompts for a real USB device to be plugged in, or simulates via a temp VHD.",
             action_external_storage, revert=revert_external_storage),
    TestCase("08", "Changing the configuration of Windows Update", "auto",
             "Changes then restores the configured active-hours-start registry value.",
             action_windows_update, setup=setup_windows_update, revert=revert_windows_update),
    TestCase("09", "Changing backup configuration", "manual",
             "Prompts for a Windows Backup setting to be toggled by hand (no safe scriptable path found).",
             action_backup_config, revert=revert_backup_config),
    TestCase("10", "Changing time / region (time zone)", "auto",
             "Changes then restores the machine's time zone via tzutil.",
             action_timezone, setup=setup_timezone, revert=revert_timezone),
    TestCase("11", "Sharing the screen (to screen/projector)", "manual",
             "Prompts for an external display to be physically/wirelessly connected.",
             action_screen, revert=revert_screen, precheck=precheck_screen),
    TestCase("12", "Application opened in admin mode", "auto",
             "Starts and closes Notepad elevated (-Verb RunAs).",
             action_admin_app),
    TestCase("13", "User took a screenshot", "auto",
             "Captures a real screenshot into Pictures\\Screenshots, then deletes it.",
             action_screenshot, revert=revert_screenshot),
    TestCase("14", "Data exported to an external location (e.g. USB)", "hybrid",
             "Prompts for a test file to be copied to a real USB drive, or simulates via a temp VHD.",
             action_data_export, revert=revert_data_export),
    TestCase("15", "Unauthorised user tried to access an admin-only resource", "auto",
             "Creates a temp admin-group account, then deliberately authenticates with the wrong password.",
             action_unauthorised, setup=setup_unauthorised, revert=revert_unauthorised),
    TestCase("16", "User added item to allow list", "auto",
             "Adds a Windows Defender exclusion path.",
             action_allowlist, revert=revert_allowlist, precheck=precheck_defender),
    TestCase("17", "User removed item from block list", "auto",
             "Pre-adds then removes a Windows Defender exclusion path.",
             action_blocklist, setup=setup_blocklist, precheck=precheck_defender),
    TestCase("18", "Modification to BitLocker drive encryption", "auto",
             "Suspends then resumes BitLocker protection on C: (skipped if C: isn't already encrypted).",
             action_bitlocker, precheck=precheck_bitlocker),
    TestCase("19", "Virus and threat protection modified", "auto",
             "Disables then re-enables Defender real-time protection.",
             action_realtime_protection, precheck=precheck_defender),
    TestCase("20", "Windows Defender settings modified", "auto",
             "Changes then restores the PUA (potentially unwanted app) protection setting.",
             action_defender_settings, setup=setup_defender_settings,
             revert=revert_defender_settings, precheck=precheck_defender),
]


def get_all_tests() -> List[TestCase]:
    return list(ALL_TESTS)
