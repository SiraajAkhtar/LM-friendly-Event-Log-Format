using System.Runtime.CompilerServices;
using System.Security.Principal;
using System.Text.RegularExpressions;
using System.Xml.Linq;

[assembly: InternalsVisibleTo("EventLogCollector.Tests")]
[assembly: InternalsVisibleTo("EventLogCollector.Gui")]

namespace EventLogCollector;

// classification of meaningful activity events
internal enum EventKind
{
    SystemStartup,
    SystemShutdownInitiated,
    SystemShutdownClean,
    SystemShutdownUnexpected,
    SystemUncleanReboot,

    LogonSuccess,
    LogonFailure,
    LogoffSession,
    LogoffUserInitiated,
    SessionLocked,
    SessionUnlocked,
    ExplicitCredentialLogon,
    PrivilegedLogonUsed,

    RdsSessionLogon,
    RdsSessionLogoff,
    RdsSessionDisconnected,
    RdsSessionReconnected,

    UserAccountCreated,
    UserAccountEnabled,
    UserAccountDisabled,
    UserAccountDeleted,
    UserAccountChanged,
    AccountNameChanged,
    PasswordChanged,
    PasswordResetAttempted,
    AccountUnlocked,
    SecurityGroupMemberAdded,
    SecurityGroupMemberRemoved,
    SecurityGroupChanged,
    AccountLockedOut,
    UserRightAssigned,
    UserRightRemoved,

    AuditLogCleared,
    AuditPolicyChanged,

    MalwareDetected,
    MalwareActionTaken,
    DefenderRealTimeProtectionDisabled,
    BehavioralDetection,
    PotentiallyUnwantedAppDetected,
    ExploitGuardBlocked,
    ControlledFolderAccessBlocked,
    DefenderConfigurationChanged,
    DefenderTamperProtectionBlocked,

    ServiceInstalled,
    ScriptBlockExecuted,
    ProcessCreated,

    ScheduledTaskCreated,
    ScheduledTaskUpdated,
    ScheduledTaskDeleted,
    ScheduledTaskDisabled,

    NetworkConnected,
    NetworkDisconnected,
    NetworkCategoryChanged,

    WifiConnected,
    WifiDisconnected,
    WifiConnectionAttemptStarted,
    WifiConnectionFailed,
    WifiAssociationStarted,
    WifiAssociationSucceeded,
    WifiAssociationFailed,
    Wifi8021xAuthStarted,
    Wifi8021xAuthSucceeded,
    Wifi8021xAuthFailed,
    Wifi8021xAuthRestarted,
    WifiSecurityStarted,
    WifiSecurityStopped,
    WifiSecuritySucceeded,
    WifiSecurityFailed,
    WifiConnectionBlocked,

    FirewallRuleAdded,
    FirewallRuleChanged,
    FirewallRuleDeleted,
    FirewallSettingChanged,
    FirewallResetToDefault,
    FirewallAllRulesDeleted,

    WindowsUpdateFound,
    WindowsUpdateDownloaded,
    WindowsUpdateInstalled,
    WindowsUpdateInstallFailed,
    WindowsUpdateDownloadFailed,

    DeviceConfigured,
    DeviceConfigurationFailed,
    DeviceConfigurationBlockedByPolicy,
    DeviceStarted,
    DeviceStartProblem,
    DeviceDeleted,
    DeviceRequiresInstallation,
    DeviceSettingsMigrated,
    DeviceSettingsNotMigrated,

    RdpConnectionStarted,
    RdpConnectionEstablished,
    RdpConnectionDisconnected,
    RdpLogonFailed,
    RdpConnectionFailed,

    SystemTimeChanged,
    ServiceStartTypeChanged,

    BitLockerEncryptionStarted,
    BitLockerEncryptionStopped,
    BitLockerProtectionSuspended,
    BitLockerProtectionResumed,
    BitLockerKeyProtectorAdded,
    BitLockerKeyProtectorRemoved,
    BitLockerVolumeLocked,
    BitLockerVolumeUnlocked,

    BackupConfigurationChanged,

    RemovableStorageDataAccessed,

    ScreenshotCaptured,
    WindowsUpdateSettingChanged,

    ApplicationCritical,
    ApplicationError,
    ApplicationWarning,
}

// how much context an eventkind is worth keeping
internal enum FidelityLevel
{
    Low,
    Medium,
    High,
}

internal readonly record struct EventClassification(EventKind Kind, FidelityLevel Fidelity);

// maps channel/eventid to a classification, builds context
internal static class EventCatalog
{
    private static readonly Dictionary<(string Channel, int EventId), EventClassification> ById = new()
    {
        // low fidelity: self-explanatory system/session activity
        [("System", 1074)] = new(EventKind.SystemShutdownInitiated, FidelityLevel.Low),
        [("System", 6005)] = new(EventKind.SystemStartup, FidelityLevel.Low),
        [("System", 6006)] = new(EventKind.SystemShutdownClean, FidelityLevel.Low),

        [("Security", 4800)] = new(EventKind.SessionLocked, FidelityLevel.Low),
        [("Security", 4801)] = new(EventKind.SessionUnlocked, FidelityLevel.Low),

        // rule 4 handles logon type
        [("Security", 4624)] = new(EventKind.LogonSuccess, FidelityLevel.Medium),
        [("Security", 4634)] = new(EventKind.LogoffSession, FidelityLevel.Medium),
        [("Security", 4647)] = new(EventKind.LogoffUserInitiated, FidelityLevel.Medium),

        [("Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", 21)] = new(EventKind.RdsSessionLogon, FidelityLevel.Medium),
        [("Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", 23)] = new(EventKind.RdsSessionLogoff, FidelityLevel.Medium),
        [("Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", 24)] = new(EventKind.RdsSessionDisconnected, FidelityLevel.Medium),
        [("Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", 25)] = new(EventKind.RdsSessionReconnected, FidelityLevel.Medium),

        // medium fidelity
        [("Microsoft-Windows-NetworkProfile/Operational", 10000)] = new(EventKind.NetworkConnected, FidelityLevel.Medium),
        [("Microsoft-Windows-NetworkProfile/Operational", 10001)] = new(EventKind.NetworkDisconnected, FidelityLevel.Medium),
        [("Microsoft-Windows-NetworkProfile/Operational", 10002)] = new(EventKind.NetworkCategoryChanged, FidelityLevel.Medium),

        // needs process creation auditing enabled
        [("Security", 4688)] = new(EventKind.ProcessCreated, FidelityLevel.Medium),

        [("Microsoft-Windows-WLAN-AutoConfig/Operational", 8001)]  = new(EventKind.WifiConnected, FidelityLevel.Medium),
        [("Microsoft-Windows-WLAN-AutoConfig/Operational", 8003)]  = new(EventKind.WifiDisconnected, FidelityLevel.Medium),
        // wifi handshake sequence
        [("Microsoft-Windows-WLAN-AutoConfig/Operational", 8000)]  = new(EventKind.WifiConnectionAttemptStarted, FidelityLevel.Medium),
        [("Microsoft-Windows-WLAN-AutoConfig/Operational", 11000)] = new(EventKind.WifiAssociationStarted, FidelityLevel.Medium),
        [("Microsoft-Windows-WLAN-AutoConfig/Operational", 11001)] = new(EventKind.WifiAssociationSucceeded, FidelityLevel.Medium),
        [("Microsoft-Windows-WLAN-AutoConfig/Operational", 12011)] = new(EventKind.Wifi8021xAuthStarted, FidelityLevel.Medium),
        [("Microsoft-Windows-WLAN-AutoConfig/Operational", 11010)] = new(EventKind.WifiSecurityStarted, FidelityLevel.Medium),
        [("Microsoft-Windows-WLAN-AutoConfig/Operational", 11004)] = new(EventKind.WifiSecurityStopped, FidelityLevel.Medium),
        [("Microsoft-Windows-WLAN-AutoConfig/Operational", 11005)] = new(EventKind.WifiSecuritySucceeded, FidelityLevel.Medium),
        [("Microsoft-Windows-WLAN-AutoConfig/Operational", 12012)] = new(EventKind.Wifi8021xAuthSucceeded, FidelityLevel.Medium),
        [("Microsoft-Windows-WLAN-AutoConfig/Operational", 12014)] = new(EventKind.Wifi8021xAuthRestarted, FidelityLevel.Medium),

        [("Microsoft-Windows-WindowsUpdateClient/Operational", 26)] = new(EventKind.WindowsUpdateFound, FidelityLevel.Medium),
        [("Microsoft-Windows-WindowsUpdateClient/Operational", 41)] = new(EventKind.WindowsUpdateDownloaded, FidelityLevel.Medium),
        [("Microsoft-Windows-WindowsUpdateClient/Operational", 19)] = new(EventKind.WindowsUpdateInstalled, FidelityLevel.Medium),

        [("Microsoft-Windows-Kernel-PnP/Configuration", 400)] = new(EventKind.DeviceConfigured, FidelityLevel.Medium),
        [("Microsoft-Windows-Kernel-PnP/Configuration", 410)] = new(EventKind.DeviceStarted, FidelityLevel.Medium),
        [("Microsoft-Windows-Kernel-PnP/Configuration", 420)] = new(EventKind.DeviceDeleted, FidelityLevel.Medium),
        [("Microsoft-Windows-Kernel-PnP/Configuration", 430)] = new(EventKind.DeviceRequiresInstallation, FidelityLevel.Medium),
        [("Microsoft-Windows-Kernel-PnP/Configuration", 442)] = new(EventKind.DeviceSettingsNotMigrated, FidelityLevel.Medium),

        [("Microsoft-Windows-TerminalServices-RDPClient/Operational", 1024)] = new(EventKind.RdpConnectionStarted, FidelityLevel.Medium),
        [("Microsoft-Windows-TerminalServices-RDPClient/Operational", 1025)] = new(EventKind.RdpConnectionEstablished, FidelityLevel.Medium),
        [("Microsoft-Windows-TerminalServices-RDPClient/Operational", 1026)] = new(EventKind.RdpConnectionDisconnected, FidelityLevel.Medium),

        [("Microsoft-Windows-Kernel-PnP/Configuration", 440)] = new(EventKind.DeviceSettingsMigrated, FidelityLevel.Low),

        [("System", 7040)] = new(EventKind.ServiceStartTypeChanged, FidelityLevel.Medium),

        // high fidelity
        [("System", 6008)] = new(EventKind.SystemShutdownUnexpected, FidelityLevel.High),
        [("System", 41)]   = new(EventKind.SystemUncleanReboot, FidelityLevel.High),
        [("System", 1)]    = new(EventKind.SystemTimeChanged, FidelityLevel.High),

        [("Security", 4625)] = new(EventKind.LogonFailure, FidelityLevel.High),

        [("Security", 4648)] = new(EventKind.ExplicitCredentialLogon, FidelityLevel.High),
        [("Security", 4672)] = new(EventKind.PrivilegedLogonUsed, FidelityLevel.High),

        [("Security", 4720)] = new(EventKind.UserAccountCreated, FidelityLevel.High),
        [("Security", 4728)] = new(EventKind.SecurityGroupMemberAdded, FidelityLevel.High), // global group
        [("Security", 4732)] = new(EventKind.SecurityGroupMemberAdded, FidelityLevel.High), // local group
        [("Security", 4756)] = new(EventKind.SecurityGroupMemberAdded, FidelityLevel.High), // universal group
        [("Security", 4740)] = new(EventKind.AccountLockedOut, FidelityLevel.High),

        [("Security", 4722)] = new(EventKind.UserAccountEnabled, FidelityLevel.High),
        [("Security", 4725)] = new(EventKind.UserAccountDisabled, FidelityLevel.High),
        [("Security", 4726)] = new(EventKind.UserAccountDeleted, FidelityLevel.High),
        [("Security", 4738)] = new(EventKind.UserAccountChanged, FidelityLevel.High),
        // rename detail lives here, not 4738
        [("Security", 4781)] = new(EventKind.AccountNameChanged, FidelityLevel.High),
        [("Security", 4723)] = new(EventKind.PasswordChanged, FidelityLevel.High),
        [("Security", 4724)] = new(EventKind.PasswordResetAttempted, FidelityLevel.High),
        [("Security", 4767)] = new(EventKind.AccountUnlocked, FidelityLevel.High),
        [("Security", 4735)] = new(EventKind.SecurityGroupChanged, FidelityLevel.High),
        [("Security", 4729)] = new(EventKind.SecurityGroupMemberRemoved, FidelityLevel.High), // global group
        [("Security", 4733)] = new(EventKind.SecurityGroupMemberRemoved, FidelityLevel.High), // local group
        [("Security", 4757)] = new(EventKind.SecurityGroupMemberRemoved, FidelityLevel.High), // universal group
        // needs authorization policy change auditing
        [("Security", 4704)] = new(EventKind.UserRightAssigned, FidelityLevel.High),
        [("Security", 4705)] = new(EventKind.UserRightRemoved, FidelityLevel.High),

        // needs security system extension auditing
        [("Security", 4697)] = new(EventKind.ServiceInstalled, FidelityLevel.High),

        [("Security", 1102)] = new(EventKind.AuditLogCleared, FidelityLevel.High),
        [("Security", 4719)] = new(EventKind.AuditPolicyChanged, FidelityLevel.High),

        [("Microsoft-Windows-Windows Defender/Operational", 1116)] = new(EventKind.MalwareDetected, FidelityLevel.High),
        [("Microsoft-Windows-Windows Defender/Operational", 1117)] = new(EventKind.MalwareActionTaken, FidelityLevel.High),
        [("Microsoft-Windows-Windows Defender/Operational", 5001)] = new(EventKind.DefenderRealTimeProtectionDisabled, FidelityLevel.High),

        [("Microsoft-Windows-Windows Defender/Operational", 1015)] = new(EventKind.BehavioralDetection, FidelityLevel.High),
        [("Microsoft-Windows-Windows Defender/Operational", 1160)] = new(EventKind.PotentiallyUnwantedAppDetected, FidelityLevel.High),
        [("Microsoft-Windows-Windows Defender/Operational", 1121)] = new(EventKind.ExploitGuardBlocked, FidelityLevel.High),
        [("Microsoft-Windows-Windows Defender/Operational", 1123)] = new(EventKind.ControlledFolderAccessBlocked, FidelityLevel.High),
        [("Microsoft-Windows-Windows Defender/Operational", 5007)] = new(EventKind.DefenderConfigurationChanged, FidelityLevel.High),
        [("Microsoft-Windows-Windows Defender/Operational", 5013)] = new(EventKind.DefenderTamperProtectionBlocked, FidelityLevel.High),

        [("Microsoft-Windows-PowerShell/Operational", 4104)] = new(EventKind.ScriptBlockExecuted, FidelityLevel.High),

        [("Microsoft-Windows-TaskScheduler/Operational", 106)] = new(EventKind.ScheduledTaskCreated, FidelityLevel.High),
        [("Microsoft-Windows-TaskScheduler/Operational", 140)] = new(EventKind.ScheduledTaskUpdated, FidelityLevel.High),
        [("Microsoft-Windows-TaskScheduler/Operational", 141)] = new(EventKind.ScheduledTaskDeleted, FidelityLevel.High),
        [("Microsoft-Windows-TaskScheduler/Operational", 142)] = new(EventKind.ScheduledTaskDisabled, FidelityLevel.High),

        // real ids, not the textbook ones
        [("Microsoft-Windows-Windows Firewall With Advanced Security/Firewall", 2097)] = new(EventKind.FirewallRuleAdded, FidelityLevel.High),
        [("Microsoft-Windows-Windows Firewall With Advanced Security/Firewall", 2099)] = new(EventKind.FirewallRuleChanged, FidelityLevel.High),
        [("Microsoft-Windows-Windows Firewall With Advanced Security/Firewall", 2052)] = new(EventKind.FirewallRuleDeleted, FidelityLevel.High),
        [("Microsoft-Windows-Windows Firewall With Advanced Security/Firewall", 2082)] = new(EventKind.FirewallSettingChanged, FidelityLevel.High), // per-profile
        [("Microsoft-Windows-Windows Firewall With Advanced Security/Firewall", 2083)] = new(EventKind.FirewallSettingChanged, FidelityLevel.High), // general
        // audit-log equivalent, needs mpssvc auditing
        [("Security", 4950)] = new(EventKind.FirewallSettingChanged, FidelityLevel.High),
        [("Microsoft-Windows-Windows Firewall With Advanced Security/Firewall", 2032)] = new(EventKind.FirewallResetToDefault, FidelityLevel.High),
        [("Microsoft-Windows-Windows Firewall With Advanced Security/Firewall", 2033)] = new(EventKind.FirewallAllRulesDeleted, FidelityLevel.High),

        [("Microsoft-Windows-WLAN-AutoConfig/Operational", 11006)] = new(EventKind.WifiSecurityFailed, FidelityLevel.High),
        [("Microsoft-Windows-WLAN-AutoConfig/Operational", 8004)]  = new(EventKind.WifiConnectionBlocked, FidelityLevel.High),
        [("Microsoft-Windows-WLAN-AutoConfig/Operational", 8002)]  = new(EventKind.WifiConnectionFailed, FidelityLevel.High),
        [("Microsoft-Windows-WLAN-AutoConfig/Operational", 11002)] = new(EventKind.WifiAssociationFailed, FidelityLevel.High),
        [("Microsoft-Windows-WLAN-AutoConfig/Operational", 12013)] = new(EventKind.Wifi8021xAuthFailed, FidelityLevel.High),

        [("Microsoft-Windows-WindowsUpdateClient/Operational", 31)] = new(EventKind.WindowsUpdateDownloadFailed, FidelityLevel.High),
        [("Microsoft-Windows-WindowsUpdateClient/Operational", 20)] = new(EventKind.WindowsUpdateInstallFailed, FidelityLevel.High),

        [("Microsoft-Windows-Kernel-PnP/Configuration", 411)] = new(EventKind.DeviceStartProblem, FidelityLevel.High),
        [("Microsoft-Windows-Kernel-PnP/Configuration", 401)] = new(EventKind.DeviceConfigurationFailed, FidelityLevel.High),
        [("Microsoft-Windows-Kernel-PnP/Configuration", 402)] = new(EventKind.DeviceConfigurationBlockedByPolicy, FidelityLevel.High),

        [("Microsoft-Windows-TerminalServices-RDPClient/Operational", 1005)] = new(EventKind.RdpLogonFailed, FidelityLevel.High),
        [("Microsoft-Windows-TerminalServices-RDPClient/Operational", 1009)] = new(EventKind.RdpLogonFailed, FidelityLevel.High),
        [("Microsoft-Windows-TerminalServices-RDPClient/Operational", 1018)] = new(EventKind.RdpConnectionFailed, FidelityLevel.High),

        // needs removable storage auditing and a registry dword
        [("Security", 4663)] = new(EventKind.RemovableStorageDataAccessed, FidelityLevel.High),

        [("Microsoft-Windows-BitLocker/BitLocker Management", 768)] = new(EventKind.BitLockerEncryptionStarted, FidelityLevel.High),
        [("Microsoft-Windows-BitLocker/BitLocker Management", 771)] = new(EventKind.BitLockerEncryptionStopped, FidelityLevel.High),
        [("Microsoft-Windows-BitLocker/BitLocker Management", 773)] = new(EventKind.BitLockerProtectionSuspended, FidelityLevel.High),
        [("Microsoft-Windows-BitLocker/BitLocker Management", 774)] = new(EventKind.BitLockerProtectionResumed, FidelityLevel.High),
        [("Microsoft-Windows-BitLocker/BitLocker Management", 775)] = new(EventKind.BitLockerKeyProtectorAdded, FidelityLevel.High),
        [("Microsoft-Windows-BitLocker/BitLocker Management", 776)] = new(EventKind.BitLockerKeyProtectorRemoved, FidelityLevel.High),
        [("Microsoft-Windows-BitLocker/BitLocker Management", 781)] = new(EventKind.BitLockerVolumeLocked, FidelityLevel.High),
        [("Microsoft-Windows-BitLocker/BitLocker Management", 782)] = new(EventKind.BitLockerVolumeUnlocked, FidelityLevel.High),

        [("Microsoft-Windows-WindowsBackup/ActionCenter", 100)] = new(EventKind.BackupConfigurationChanged, FidelityLevel.Medium),
        [("Microsoft-Windows-WindowsBackup/ActionCenter", 101)] = new(EventKind.BackupConfigurationChanged, FidelityLevel.Medium),
    };

    public static bool TryClassify(string channel, int eventId, out EventClassification classification)
        => ById.TryGetValue((channel, eventId), out classification);

    // fixed description, native message is not a sentence
    private static readonly Dictionary<EventKind, string> DescriptionOverrides = new()
    {
        [EventKind.BackupConfigurationChanged] = "A Windows Backup configuration setting was changed.",
    };

    public static bool TryGetDescriptionOverride(EventKind kind, out string description)
        => DescriptionOverrides.TryGetValue(kind, out description!);

    public static bool TryClassifyApplication(byte? level, out EventClassification classification)
    {
        switch (level)
        {
            case 1: classification = new(EventKind.ApplicationCritical, FidelityLevel.High); return true;
            case 2: classification = new(EventKind.ApplicationError, FidelityLevel.High); return true;
            case 3: classification = new(EventKind.ApplicationWarning, FidelityLevel.Medium); return true;
            default: classification = default; return false;
        }
    }

    // builds context dict sized to fidelity tier
    public static Dictionary<string, string> BuildContext(
        FidelityLevel fidelity, string? provider, string? channel, string xml)
    {
        var context = new Dictionary<string, string>
        {
            ["provider"] = provider ?? string.Empty,
            ["channel"]  = channel ?? string.Empty,
        };

        if (fidelity >= FidelityLevel.Medium)
        {
            foreach (var (key, value) in ExtractNamedFields(xml))
            {
                if (context.ContainsKey(key))
                    continue; // don't clobber provider/channel
                context[key] = value;
            }
        }

        return context;
    }

    // raw unresolved codes/guids are dropped, not guessed at
    private static readonly Regex HexCodePattern = new(@"^0x[0-9a-fA-F]+$", RegexOptions.Compiled);
    private static readonly Regex MessageTableCodePattern = new(@"^%%\d+$", RegexOptions.Compiled);
    private static readonly Regex GuidPattern = new(
        @"^\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?$",
        RegexOptions.Compiled);

    // logon type is a fixed constant set, translated not dropped
    private static readonly Dictionary<string, string> LogonTypeNames = new()
    {
        ["2"]  = "Interactive",
        ["3"]  = "Network",
        ["4"]  = "Batch",
        ["5"]  = "Service",
        ["7"]  = "Unlock",
        ["8"]  = "NetworkCleartext",
        ["9"]  = "NewCredentials",
        ["10"] = "RemoteInteractive (RDP)",
        ["11"] = "CachedInteractive",
        ["12"] = "CachedRemoteInteractive",
        ["13"] = "CachedUnlock",
    };

    // token elevation type, fixed 3-value constant
    private static readonly Dictionary<string, string> TokenElevationTypeNames = new()
    {
        ["%%1936"] = "Full (UAC off or built-in admin/system account)",
        ["%%1937"] = "Elevated (Run as administrator)",
        ["%%1938"] = "Limited (standard, not elevated)",
    };

    // logon failure substatus codes
    private static readonly Dictionary<string, string> LogonFailureCodeNames = new(StringComparer.OrdinalIgnoreCase)
    {
        ["0xC000006A"] = "incorrect password",
        ["0xC0000064"] = "user name does not exist",
        ["0xC0000234"] = "account locked out",
        ["0xC0000072"] = "account disabled",
        ["0xC0000193"] = "account expired",
        ["0xC0000071"] = "password expired",
        ["0xC000006F"] = "logon outside authorized hours",
        ["0xC0000070"] = "workstation restriction",
    };

    // primary group rid, fixed constant set
    private static readonly Dictionary<string, string> WellKnownGroupRids = new()
    {
        ["500"] = "Administrator",
        ["501"] = "Guest",
        ["512"] = "Domain Admins",
        ["513"] = "Domain Users",
        ["514"] = "Domain Guests",
        ["515"] = "Domain Computers",
        ["516"] = "Domain Controllers",
        ["517"] = "Cert Publishers",
        ["518"] = "Schema Admins",
        ["519"] = "Enterprise Admins",
        ["520"] = "Group Policy Creator Owners",
        ["553"] = "RAS and IAS Servers",
    };

    // best-effort translation for a known coded field
    private static string? TryTranslateKnownCode(string fieldName, string rawValue) => fieldName switch
    {
        "LogonType" => LogonTypeNames.TryGetValue(rawValue, out var logonType) ? logonType : null,
        "SubStatus" or "Status" => LogonFailureCodeNames.TryGetValue(rawValue, out var reason) ? reason : null,
        "PrimaryGroupId" => WellKnownGroupRids.TryGetValue(rawValue, out var groupName) ? groupName : null,
        "TokenElevationType" => TokenElevationTypeNames.TryGetValue(rawValue, out var elevation) ? elevation : null,
        _ => null,
    };

    // bare "-" placeholder, unresolved
    private static readonly Regex DashPlaceholderPattern = new(@"^-+$", RegexOptions.Compiled);

    // sids resolved to account names when possible
    private static readonly Regex SidPattern = new(@"^S-\d+-\d+(-\d+)*$", RegexOptions.Compiled);

    private static string? TryResolveSidToAccountName(string sidValue)
    {
        try
        {
            var sid = new SecurityIdentifier(sidValue);
            return ((NTAccount)sid.Translate(typeof(NTAccount))).Value;
        }
        catch
        {
            return null; // unresolvable, drop
        }
    }

    // pulls named leaf fields out of eventdata/userdata xml
    private static Dictionary<string, string> ExtractNamedFields(string xml)
    {
        var fields = new Dictionary<string, string>();
        if (string.IsNullOrEmpty(xml))
            return fields;

        try
        {
            var root = XDocument.Parse(xml).Root;
            var dataSection = root?.Elements()
                .FirstOrDefault(e => e.Name.LocalName is "EventData" or "UserData");
            if (dataSection is null)
                return fields;

            foreach (var leaf in dataSection.Descendants().Where(e => !e.HasElements))
            {
                if (leaf.Name.LocalName == "Binary")
                    continue;

                var name = leaf.Attribute("Name")?.Value;
                string key;
                if (!string.IsNullOrWhiteSpace(name))
                    key = name!;
                else if (leaf.Name.LocalName == "Data")
                    continue; // unnamed positional placeholder
                else
                    key = leaf.Name.LocalName;

                var value = leaf.Value.Trim();
                if (string.IsNullOrEmpty(value))
                    continue;

                if (TryTranslateKnownCode(key, value) is string translated)
                {
                    fields[key] = translated;
                    continue;
                }

                if (HexCodePattern.IsMatch(value) || MessageTableCodePattern.IsMatch(value)
                    || GuidPattern.IsMatch(value) || DashPlaceholderPattern.IsMatch(value))
                    continue;

                if (SidPattern.IsMatch(value))
                {
                    if (TryResolveSidToAccountName(value) is string accountName)
                        fields[key] = accountName;
                    continue;
                }

                fields[key] = value;
            }
        }
        catch
        {
            // malformed xml, best-effort
        }

        return fields;
    }
}
