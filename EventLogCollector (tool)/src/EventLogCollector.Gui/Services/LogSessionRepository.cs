using System.IO;
using EventLogCollector;
using EventLogCollector.Gui.Models;

namespace EventLogCollector.Gui.Services;

// reads session csvs from logs folder
internal sealed class LogSessionRepository(LogFolderSettings settings)
{
    public string LogsDirectory => settings.LogsDirectory;

    public static string SidecarPathFor(string csvPath)
        => Path.Combine(
            Path.GetDirectoryName(csvPath)!,
            Path.GetFileNameWithoutExtension(csvPath) + ".correlation.ndjson");

    // all rows sorted by timestamp
    public async Task<List<LogEntryRow>> LoadAllRowsAsync(string? excludeFilePath = null, CancellationToken ct = default)
    {
        var rows = new List<LogEntryRow>();

        foreach (var path in EnumerateSessionFiles(excludeFilePath))
        {
            await foreach (var entry in EventCsvReader.ReadAsync(path, ct).ConfigureAwait(false))
            {
                rows.Add(new LogEntryRow
                {
                    Timestamp = entry.Timestamp,
                    Description = entry.Description,
                    ContextDict = entry.Context,
                    SourceFilePath = path,
                });
            }
        }

        rows.Sort((a, b) => a.Timestamp.CompareTo(b.Timestamp));
        return rows;
    }

    // rows joined with sidecar correlation data
    public async Task<List<(LogEntryRow Row, EventKind? Kind, CorrelationIds Ids)>> LoadAllRowsWithCorrelationAsync(
        string? excludeFilePath = null, CancellationToken ct = default)
    {
        var result = new List<(LogEntryRow, EventKind?, CorrelationIds)>();

        foreach (var path in EnumerateSessionFiles(excludeFilePath))
        {
            var sidecarRecords = await CorrelationSidecarReader.ReadAsync(SidecarPathFor(path), ct).ConfigureAwait(false);
            var byTimestamp = new Dictionary<DateTimeOffset, List<SidecarRecord>>();
            foreach (var record in sidecarRecords)
            {
                var key = TruncateToSecond(record.Timestamp);
                if (!byTimestamp.TryGetValue(key, out var list))
                    byTimestamp[key] = list = [];
                list.Add(record);
            }

            await foreach (var entry in EventCsvReader.ReadAsync(path, ct).ConfigureAwait(false))
            {
                var row = new LogEntryRow
                {
                    Timestamp = entry.Timestamp,
                    Description = entry.Description,
                    ContextDict = entry.Context,
                    SourceFilePath = path,
                };

                var (kind, ids) = MatchSidecar(byTimestamp, entry.Timestamp, entry.Description);
                result.Add((row, kind, ids));
            }
        }

        result.Sort((a, b) => a.Item1.Timestamp.CompareTo(b.Item1.Timestamp));
        return result;
    }

    private IEnumerable<string> EnumerateSessionFiles(string? excludeFilePath)
    {
        if (!Directory.Exists(LogsDirectory))
            yield break;

        foreach (var path in Directory.EnumerateFiles(LogsDirectory, "*.csv"))
        {
            if (excludeFilePath is not null && string.Equals(path, excludeFilePath, StringComparison.OrdinalIgnoreCase))
                continue;
            yield return path;
        }
    }

    private static DateTimeOffset TruncateToSecond(DateTimeOffset ts)
        => ts - TimeSpan.FromTicks(ts.Ticks % TimeSpan.TicksPerSecond);

    private static (EventKind? Kind, CorrelationIds Ids) MatchSidecar(
        Dictionary<DateTimeOffset, List<SidecarRecord>> byTimestamp, DateTimeOffset timestamp, string description)
    {
        if (!byTimestamp.TryGetValue(timestamp, out var candidates) || candidates.Count == 0)
            return (null, default);

        int index = candidates.FindIndex(r => r.Description == description);
        if (index < 0) index = 0;

        var record = candidates[index];
        candidates.RemoveAt(index);

        var kind = Enum.TryParse<EventKind>(record.Kind, out var parsedKind) ? parsedKind : (EventKind?)null;
        return (kind, new CorrelationIds(record.LogonId, record.ProcessId, record.InterfaceGuid));
    }
}
