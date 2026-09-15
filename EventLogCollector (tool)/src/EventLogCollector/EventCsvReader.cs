using System.Runtime.CompilerServices;

namespace EventLogCollector;

// reads the csv format eventcsvwriter produces
public static class EventCsvReader
{
    public static async IAsyncEnumerable<CsvEntry> ReadAsync(
        string path, [EnumeratorCancellation] CancellationToken ct = default)
    {
        string content;
        using (var stream = new FileStream(
            path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, bufferSize: 65_536, useAsync: true))
        using (var reader = new StreamReader(stream))
        {
            content = await reader.ReadToEndAsync(ct).ConfigureAwait(false);
        }

        bool isHeader = true;
        foreach (var rawFields in CsvFormat.ParseRecords(content))
        {
            ct.ThrowIfCancellationRequested();

            if (isHeader)
            {
                isHeader = false;
                continue;
            }

            if (rawFields.Count < 3)
                continue;

            var timestamp = CsvFormat.ParseTimestamp(rawFields[0]);
            var description = rawFields[1];
            var context = rawFields[2].Length > 0
                ? CsvFormat.DeserializeContext(rawFields[2])
                : null;

            yield return new CsvEntry(timestamp, description, context);
        }
    }
}
