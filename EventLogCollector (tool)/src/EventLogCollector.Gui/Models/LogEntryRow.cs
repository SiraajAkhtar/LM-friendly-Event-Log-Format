namespace EventLogCollector.Gui.Models;

// log grid row
internal sealed class LogEntryRow
{
    public required DateTimeOffset Timestamp { get; set; }

    // local display of utc timestamp
    public DateTimeOffset LocalTimestamp => Timestamp.ToLocalTime();

    public required string Description { get; set; }
    public IReadOnlyDictionary<string, string>? ContextDict { get; set; }
    public required string SourceFilePath { get; set; }

    // page 3 correlation group
    public string GroupLabel { get; set; } = string.Empty;

    // flattened context summary
    public string Context => ContextDict is { Count: > 0 }
        ? string.Join("; ", ContextDict.Select(kv => $"{kv.Key}={SingleLine(kv.Value)}"))
        : string.Empty;

    // collapse newlines for grid display
    internal static string SingleLine(string value)
        => value.IndexOfAny(['\r', '\n']) < 0 ? value : value.Replace("\r\n", " ").Replace('\r', ' ').Replace('\n', ' ');
}
