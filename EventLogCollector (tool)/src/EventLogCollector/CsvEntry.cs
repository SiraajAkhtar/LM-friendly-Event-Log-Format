namespace EventLogCollector;

// one csv row
public sealed record CsvEntry(
    DateTimeOffset Timestamp,
    string Description,
    IReadOnlyDictionary<string, string>? Context = null
);
