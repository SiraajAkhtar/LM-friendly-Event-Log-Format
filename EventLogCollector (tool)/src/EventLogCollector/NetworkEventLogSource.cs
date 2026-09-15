using System.Diagnostics.Eventing.Reader;

namespace EventLogCollector;

// watches network log channels, writes csv rows
public sealed class NetworkEventLogSource : IDisposable
{
    // default network channels
    public static readonly string[] DefaultChannels =
    [
        "Microsoft-Windows-NetworkProfile/Operational",                        // connect/disconnect
        "Microsoft-Windows-DHCP-Client/Admin",                                 // ip lease events
        "Microsoft-Windows-WLAN-AutoConfig/Operational",                       // wifi/airplane mode
        "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",  // firewall changes
    ];

    private readonly EventCsvWriter _writer;
    private readonly EventLogWatcher[] _watchers;

    // in-memory hook for internal consumers
    internal event Action<CapturedEntry>? EntryCaptured;

    public NetworkEventLogSource(EventCsvWriter writer, string[]? channels = null)
    {
        _writer = writer;
        _watchers = Subscribe(channels ?? DefaultChannels);
    }

    public void Dispose()
    {
        foreach (var w in _watchers)
        {
            w.Enabled = false;
            w.Dispose();
        }
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

        string rawMessage;
        try   { rawMessage = record.FormatDescription() ?? string.Empty; }
        catch { rawMessage = string.Empty; }
        string description = EventDescriptionFormatter.ToFriendlyDescription(rawMessage);

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
                // channel not registered, skip
            }
        }
        return [.. list];
    }
}
