using System.Diagnostics.Eventing.Reader;

namespace EventLogCollector;

// watches os log channels, writes csv rows
public sealed class OsEventLogSource : IDisposable
{
    // default os channels, security needs admin
    public static readonly string[] DefaultChannels =
    [
        "System",                                                               // hardware/drivers/services
        "Security",                                                             // lock/logon events, admin-only
        "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",  // session lock/connect
        "Microsoft-Windows-Windows Defender/Operational",                      // malware detections
        "Microsoft-Windows-PowerShell/Operational",                            // script execution
        "Microsoft-Windows-TaskScheduler/Operational",                         // scheduled task events
        "Microsoft-Windows-Kernel-PnP/Configuration",                          // device/usb events
        "Microsoft-Windows-TerminalServices-RDPClient/Operational",            // outbound rdp
        "Microsoft-Windows-WindowsUpdateClient/Operational",                   // update events
        "Microsoft-Windows-BitLocker/BitLocker Management",                    // encryption events
        "Microsoft-Windows-WindowsBackup/ActionCenter",                        // backup app status
    ];

    private readonly EventCsvWriter _writer;
    private readonly EventLogWatcher[] _watchers;
    private readonly AccountAttributeTracker _accountTracker;

    // in-memory hook for internal consumers
    internal event Action<CapturedEntry>? EntryCaptured;

    public OsEventLogSource(EventCsvWriter writer, string[]? channels = null)
    {
        _writer = writer;
        _accountTracker = new AccountAttributeTracker();
        _accountTracker.SeedAll();
        _watchers = Subscribe(channels ?? DefaultChannels);
    }

    public void Dispose()
    {
        foreach (var w in _watchers)
        {
            w.Enabled = false;
            w.Dispose();
        }
        _accountTracker.Dispose();
    }

    // runs on etw background thread
    private void OnEventRecordWritten(object? sender, EventRecordWrittenEventArgs e)
    {
        if (e.EventException is not null || e.EventRecord is null) return;

        using var record = e.EventRecord;

        if (!EventCatalog.TryClassify(record.LogName ?? string.Empty, record.Id, out var classification))
            return;

        string xml = string.Empty;
        if (classification.Fidelity >= FidelityLevel.Medium)
        {
            try   { xml = record.ToXml(); }
            catch { xml = string.Empty; }
        }

        var context = EventCatalog.BuildContext(
            classification.Fidelity, record.ProviderName, record.LogName, xml);

        // 4738 doesn't say which attribute changed, diff against tracked snapshot
        if (classification.Kind == EventKind.UserAccountChanged
            && context.TryGetValue("TargetUserName", out var accountName)
            && _accountTracker.TryObserve(accountName, out var changedFields))
        {
            foreach (var (key, value) in changedFields)
                context[key] = value;
        }

        string description;
        if (EventCatalog.TryGetDescriptionOverride(classification.Kind, out var overrideText))
        {
            description = overrideText;
        }
        else
        {
            string rawMessage;
            try   { rawMessage = record.FormatDescription() ?? string.Empty; }
            catch { rawMessage = string.Empty; }
            description = EventDescriptionFormatter.ToFriendlyDescription(rawMessage);
        }

        // convert local time to utc
        var timestamp = record.TimeCreated.HasValue
            ? new DateTimeOffset(record.TimeCreated.Value.ToUniversalTime(), TimeSpan.Zero)
            : DateTimeOffset.UtcNow;

        var entry = new CsvEntry(timestamp, description, context);
        var ids = EventCorrelationEngine.Extract(record, classification.Kind);

        _writer.TryWrite(entry);
        EntryCaptured?.Invoke(new CapturedEntry(entry, classification.Kind, ids));
    }

    private EventLogWatcher[] Subscribe(string[] channels)
    {
        var list = new List<EventLogWatcher>(channels.Length);
        foreach (var channel in channels)
        {
            try
            {
                var query = new EventLogQuery(channel, PathType.LogName, "*");
                var watcher = new EventLogWatcher(query);
                watcher.EventRecordWritten += OnEventRecordWritten;
                watcher.Enabled = true;
                list.Add(watcher);
            }
            catch
            {
                // channel unavailable or access denied, skip
            }
        }
        return [.. list];
    }
}
