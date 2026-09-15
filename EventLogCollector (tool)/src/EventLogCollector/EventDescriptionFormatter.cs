using System.Text.RegularExpressions;

namespace EventLogCollector;

// cleans a raw event message into one plain sentence
internal static class EventDescriptionFormatter
{
    private static readonly string[] LineBreaks = ["\r\n", "\r", "\n"];

    private static readonly Regex HexCode = new(@"0x[0-9a-f]+", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly Regex EmptyParens = new(@"\(\s*\)", RegexOptions.Compiled);

    private static readonly Dictionary<string, string> Abbreviations = new()
    {
        ["DHCP"] = "network management service",
        ["WLAN"] = "wireless network",
        ["NIC"]  = "network adapter",
        ["LAN"]  = "local network",
        ["WAN"]  = "wide area network",
        ["VPN"]  = "virtual private network",
        ["GUID"] = "unique identifier",
        ["SID"]  = "security identifier",
        ["PID"]  = "process identifier",
        ["URL"]  = "web address",
    };

    private static readonly Regex AbbreviationPattern = new(
        @"\b(" + string.Join("|", Abbreviations.Keys.Select(Regex.Escape)) + @")\b",
        RegexOptions.Compiled);

    // system pseudo-accounts
    private static readonly Regex SystemAccount = new(
        @"NT AUTHORITY\\(SYSTEM|LOCAL SERVICE|NETWORK SERVICE)|NT SERVICE\\[^\s,;]+",
        RegexOptions.Compiled);

    private static readonly Regex Whitespace = new(@"\s+", RegexOptions.Compiled);
    private static readonly Regex SpaceBeforePunctuation = new(@"\s+([,.;:])", RegexOptions.Compiled);

    public static string ToFriendlyDescription(string? rawMessage)
    {
        if (string.IsNullOrWhiteSpace(rawMessage))
            return string.Empty;

        // header line only, rest belongs in context
        string headerLine = rawMessage
            .Split(LineBreaks, StringSplitOptions.None)
            .FirstOrDefault(line => !string.IsNullOrWhiteSpace(line)) ?? rawMessage;

        string text = Whitespace.Replace(headerLine, " ").Trim();

        text = HexCode.Replace(text, string.Empty);
        text = EmptyParens.Replace(text, string.Empty);
        text = AbbreviationPattern.Replace(text, m => Abbreviations[m.Value]);
        text = SystemAccount.Replace(text, "a core system process");

        // cleanup doubled spaces
        text = Whitespace.Replace(text, " ");
        text = SpaceBeforePunctuation.Replace(text, "$1");

        return text.Trim();
    }
}
