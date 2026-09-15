using System.Diagnostics.Eventing.Reader;

namespace EventLogCollector;

// native correlation ids, in-memory only
internal readonly record struct CorrelationIds(
    string? LogonId,
    int? ProcessId,
    string? InterfaceGuid)
{
    public bool IsEmpty => LogonId is null && ProcessId is null && InterfaceGuid is null;
}

// one raw event queued for correlation indexing
internal readonly record struct CorrelatableLogEntry(int Id, DateTimeOffset Timestamp, EventKind Kind, EventRecord Record);

// index-ready form, ids only
internal readonly record struct CorrelatableEvent(int Id, DateTimeOffset Timestamp, CorrelationIds Ids);

// a written csv entry paired with its correlation ids
internal readonly record struct CapturedEntry(CsvEntry Entry, EventKind Kind, CorrelationIds Ids);

// how two indexed events relate
internal enum CorrelationMatchType
{
    SameLogonId,
    SameProcessId,
    SameInterfaceGuid,
    TimeProximity,
}

// a discovered in-memory link between two events
internal readonly record struct CorrelationLink(int EventIdA, int EventIdB, CorrelationMatchType MatchType);

// lookup structure built by index()
internal sealed class CorrelationIndex
{
    public IReadOnlyList<CorrelatableEvent> EventsByTime { get; }
    public IReadOnlyDictionary<string, List<CorrelatableEvent>> ByLogonId { get; }
    public IReadOnlyDictionary<int, List<CorrelatableEvent>> ByProcessId { get; }
    public IReadOnlyDictionary<string, List<CorrelatableEvent>> ByInterfaceGuid { get; }

    internal CorrelationIndex(
        List<CorrelatableEvent> eventsByTime,
        Dictionary<string, List<CorrelatableEvent>> byLogonId,
        Dictionary<int, List<CorrelatableEvent>> byProcessId,
        Dictionary<string, List<CorrelatableEvent>> byInterfaceGuid)
    {
        EventsByTime = eventsByTime;
        ByLogonId = byLogonId;
        ByProcessId = byProcessId;
        ByInterfaceGuid = byInterfaceGuid;
    }
}

// in-memory correlation of native windows ids, never touches the csv
internal static class EventCorrelationEngine
{
    public static readonly TimeSpan DefaultDirectIdWindow = TimeSpan.FromMinutes(30);
    public static readonly TimeSpan DefaultProximityWindow = TimeSpan.FromSeconds(4);

    private static readonly Dictionary<EventKind, string> LogonIdField = new()
    {
        [EventKind.LogonSuccess]        = "TargetLogonId",
        [EventKind.LogonFailure]        = "TargetLogonId",
        [EventKind.LogoffSession]       = "TargetLogonId",
        [EventKind.LogoffUserInitiated] = "TargetLogonId",
        [EventKind.SessionLocked]       = "TargetLogonId",
        [EventKind.SessionUnlocked]     = "TargetLogonId",
    };

    private static readonly Dictionary<EventKind, string> InterfaceGuidField = new()
    {
        [EventKind.WifiConnected]       = "InterfaceGuid",
        [EventKind.WifiDisconnected]    = "InterfaceGuid",
        [EventKind.NetworkConnected]    = "Guid",
        [EventKind.NetworkDisconnected] = "Guid",
    };

    // best-effort id extraction, never throws
    public static CorrelationIds Extract(EventRecord record, EventKind kind)
    {
        string? logonId = LogonIdField.TryGetValue(kind, out var logonField)
            ? TryGetFieldValue(record, logonField)
            : null;

        string? interfaceGuid = InterfaceGuidField.TryGetValue(kind, out var guidField)
            ? TryGetFieldValue(record, guidField)
            : null;

        int? processId;
        try   { processId = record.ProcessId; }
        catch { processId = null; }

        return new CorrelationIds(logonId, processId, interfaceGuid);
    }

    // extracts ids from every entry, builds the index
    public static CorrelationIndex Index(IEnumerable<CorrelatableLogEntry> entries)
        => Index(entries.Select(e => new CorrelatableEvent(e.Id, e.Timestamp, Extract(e.Record, e.Kind))));

    // builds the index from already-extracted events
    public static CorrelationIndex Index(IEnumerable<CorrelatableEvent> events)
    {
        var eventsByTime = events.OrderBy(e => e.Timestamp).ToList();

        var byLogonId = new Dictionary<string, List<CorrelatableEvent>>();
        var byProcessId = new Dictionary<int, List<CorrelatableEvent>>();
        var byInterfaceGuid = new Dictionary<string, List<CorrelatableEvent>>();

        foreach (var indexed in eventsByTime)
        {
            if (indexed.Ids.LogonId is string logonId)
                AddTo(byLogonId, logonId, indexed);
            if (indexed.Ids.ProcessId is int processId)
                AddTo(byProcessId, processId, indexed);
            if (indexed.Ids.InterfaceGuid is string interfaceGuid)
                AddTo(byInterfaceGuid, interfaceGuid, indexed);
        }

        return new CorrelationIndex(eventsByTime, byLogonId, byProcessId, byInterfaceGuid);
    }

    // finds direct id matches and time-proximity matches
    public static IReadOnlyList<CorrelationLink> FindLinks(
        CorrelationIndex index, TimeSpan? directIdWindow = null, TimeSpan? proximityWindow = null)
    {
        var links = new List<CorrelationLink>();
        var seenPairs = new HashSet<(int, int)>();

        var directWindow = directIdWindow ?? DefaultDirectIdWindow;
        var proxWindow = proximityWindow ?? DefaultProximityWindow;

        AddDirectIdLinks(index.ByLogonId, CorrelationMatchType.SameLogonId, directWindow, links, seenPairs);
        AddDirectIdLinks(index.ByProcessId, CorrelationMatchType.SameProcessId, directWindow, links, seenPairs);
        AddDirectIdLinks(index.ByInterfaceGuid, CorrelationMatchType.SameInterfaceGuid, directWindow, links, seenPairs);

        AddProximityLinks(index.EventsByTime, proxWindow, links, seenPairs);

        return links;
    }

    private static void AddTo<TKey>(Dictionary<TKey, List<CorrelatableEvent>> map, TKey key, CorrelatableEvent value)
        where TKey : notnull
    {
        if (!map.TryGetValue(key, out var list))
        {
            list = new List<CorrelatableEvent>();
            map[key] = list;
        }
        list.Add(value);
    }

    // consecutive-pair check, list already time-ordered
    private static void AddDirectIdLinks<TKey>(
        IReadOnlyDictionary<TKey, List<CorrelatableEvent>> groups,
        CorrelationMatchType matchType,
        TimeSpan window,
        List<CorrelationLink> links,
        HashSet<(int, int)> seenPairs)
        where TKey : notnull
    {
        foreach (var group in groups.Values)
        {
            for (int i = 1; i < group.Count; i++)
            {
                var prev = group[i - 1];
                var curr = group[i];
                if (curr.Timestamp - prev.Timestamp > window)
                    continue;

                var pair = OrderedPair(prev.Id, curr.Id);
                if (seenPairs.Add(pair))
                    links.Add(new CorrelationLink(pair.Item1, pair.Item2, matchType));
            }
        }
    }

    // sliding window over the sorted event list
    private static void AddProximityLinks(
        IReadOnlyList<CorrelatableEvent> eventsByTime,
        TimeSpan window,
        List<CorrelationLink> links,
        HashSet<(int, int)> seenPairs)
    {
        for (int i = 0; i < eventsByTime.Count; i++)
        {
            for (int j = i + 1; j < eventsByTime.Count; j++)
            {
                if (eventsByTime[j].Timestamp - eventsByTime[i].Timestamp > window)
                    break;

                if (SharesAnyId(eventsByTime[i].Ids, eventsByTime[j].Ids))
                    continue;

                var pair = OrderedPair(eventsByTime[i].Id, eventsByTime[j].Id);
                if (seenPairs.Add(pair))
                    links.Add(new CorrelationLink(pair.Item1, pair.Item2, CorrelationMatchType.TimeProximity));
            }
        }
    }

    private static bool SharesAnyId(CorrelationIds a, CorrelationIds b)
        => (a.LogonId is not null && a.LogonId == b.LogonId)
        || (a.ProcessId is not null && a.ProcessId == b.ProcessId)
        || (a.InterfaceGuid is not null && a.InterfaceGuid == b.InterfaceGuid);

    private static (int, int) OrderedPair(int a, int b) => a <= b ? (a, b) : (b, a);

    private static string? TryGetFieldValue(EventRecord record, string fieldName)
    {
        if (record is not EventLogRecord logRecord)
            return null;

        try
        {
            var selector = new EventLogPropertySelector(new[] { $"Event/EventData/Data[@Name='{fieldName}']" });
            var values = logRecord.GetPropertyValues(selector);
            object? value = values.Count > 0 ? values[0] : null;

            return value switch
            {
                null => null,
                byte[] bytes => Convert.ToHexString(bytes),
                _ => value.ToString(),
            };
        }
        catch
        {
            // field absent or unreadable
            return null;
        }
    }
}
