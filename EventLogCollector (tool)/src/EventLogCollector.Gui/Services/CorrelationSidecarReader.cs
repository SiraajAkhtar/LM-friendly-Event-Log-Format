using System.IO;
using System.Text.Json;

namespace EventLogCollector.Gui.Services;

// reads correlation sidecar file
internal static class CorrelationSidecarReader
{
    public static async Task<IReadOnlyList<SidecarRecord>> ReadAsync(string path, CancellationToken ct = default)
    {
        if (!File.Exists(path))
            return [];

        var lines = await File.ReadAllLinesAsync(path, ct).ConfigureAwait(false);
        var records = new List<SidecarRecord>(lines.Length);

        foreach (var line in lines)
        {
            if (string.IsNullOrWhiteSpace(line))
                continue;

            try
            {
                if (JsonSerializer.Deserialize<SidecarRecord>(line) is { } record)
                    records.Add(record);
            }
            catch (JsonException)
            {
                // malformed line, skip
            }
        }

        return records;
    }
}
