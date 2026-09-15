using System.Globalization;
using System.Text;

namespace EventLogCollector;

// csv escaping and parsing
internal static class CsvFormat
{
    // timestamp format
    public const string TimestampFormat = "d/M/yy HH:mm:ss";

    // rfc 4180 field escaping
    public static string Escape(string field)
    {
        if (field.Contains(',') || field.Contains('"') || field.Contains('\n') || field.Contains('\r'))
            return $"\"{field.Replace("\"", "\"\"")}\"";
        return field;
    }

    // context dict to key=val;key=val
    public static string SerializeContext(IReadOnlyDictionary<string, string> ctx)
        => string.Join(";", ctx.Select(kv =>
            $"{Uri.EscapeDataString(kv.Key)}={Uri.EscapeDataString(kv.Value)}"));

    // inverse of serializecontext
    public static Dictionary<string, string> DeserializeContext(string serialized)
    {
        var context = new Dictionary<string, string>();
        if (string.IsNullOrEmpty(serialized))
            return context;

        foreach (var pair in serialized.Split(';'))
        {
            if (pair.Length == 0) continue;
            int eq = pair.IndexOf('=');
            if (eq < 0) continue;

            string key = Uri.UnescapeDataString(pair[..eq]);
            string value = Uri.UnescapeDataString(pair[(eq + 1)..]);
            context[key] = value;
        }

        return context;
    }

    // splits csv text into raw field records
    public static IEnumerable<List<string>> ParseRecords(string csvText)
    {
        var fields = new List<string>();
        var current = new StringBuilder();
        bool inQuotes = false;
        bool sawAnyContent = false;

        int i = 0;
        while (i < csvText.Length)
        {
            char ch = csvText[i];
            sawAnyContent = true;

            if (inQuotes)
            {
                if (ch == '"')
                {
                    if (i + 1 < csvText.Length && csvText[i + 1] == '"')
                    {
                        current.Append('"');
                        i += 2;
                        continue;
                    }
                    inQuotes = false;
                    i++;
                    continue;
                }
                current.Append(ch);
                i++;
                continue;
            }

            switch (ch)
            {
                case '"':
                    inQuotes = true;
                    i++;
                    break;
                case ',':
                    fields.Add(current.ToString());
                    current.Clear();
                    i++;
                    break;
                case '\r':
                case '\n':
                    if (ch == '\r' && i + 1 < csvText.Length && csvText[i + 1] == '\n')
                        i++;
                    i++;
                    fields.Add(current.ToString());
                    current.Clear();
                    yield return fields;
                    fields = new List<string>();
                    sawAnyContent = false;
                    break;
                default:
                    current.Append(ch);
                    i++;
                    break;
            }
        }

        if (sawAnyContent || current.Length > 0)
        {
            fields.Add(current.ToString());
            yield return fields;
        }
    }

    // parses a timestamp written by eventcsvwriter
    public static DateTimeOffset ParseTimestamp(string text)
    {
        var dateTime = DateTime.ParseExact(text, TimestampFormat, CultureInfo.InvariantCulture);
        return new DateTimeOffset(dateTime, TimeSpan.Zero);
    }
}
