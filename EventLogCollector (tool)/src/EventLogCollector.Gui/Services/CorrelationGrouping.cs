using EventLogCollector;
using EventLogCollector.Gui.Models;

namespace EventLogCollector.Gui.Services;

// groups rows into connected components
internal static class CorrelationGrouping
{
    // assigns grouplabel in place
    public static void AssignGroups(
        IReadOnlyList<LogEntryRow> rows,
        IReadOnlyList<CorrelationIds> correlationData)
    {
        if (rows.Count != correlationData.Count)
            throw new ArgumentException("rows and correlationData must be the same length and index-aligned.");

        if (rows.Count == 0)
            return;

        var events = rows.Select((row, i) => new CorrelatableEvent(i, row.Timestamp, correlationData[i])).ToList();
        var index = EventCorrelationEngine.Index(events);
        var links = EventCorrelationEngine.FindLinks(index);

        var parent = new int[rows.Count];
        for (int i = 0; i < parent.Length; i++)
            parent[i] = i;

        int Find(int x)
        {
            while (parent[x] != x)
            {
                parent[x] = parent[parent[x]];
                x = parent[x];
            }
            return x;
        }

        void Union(int a, int b)
        {
            a = Find(a);
            b = Find(b);
            if (a != b) parent[a] = b;
        }

        var matchTypesByRoot = new Dictionary<int, List<CorrelationMatchType>>();
        foreach (var link in links)
        {
            Union(link.EventIdA, link.EventIdB);
        }
        foreach (var link in links)
        {
            int root = Find(link.EventIdA);
            if (!matchTypesByRoot.TryGetValue(root, out var types))
                matchTypesByRoot[root] = types = [];
            types.Add(link.MatchType);
        }

        var membersByRoot = new Dictionary<int, List<int>>();
        for (int i = 0; i < rows.Count; i++)
        {
            int root = Find(i);
            if (!membersByRoot.TryGetValue(root, out var members))
                membersByRoot[root] = members = [];
            members.Add(i);
        }

        int groupNumber = 0;
        foreach (var (root, members) in membersByRoot.OrderBy(kv => rows[kv.Value.Min()].Timestamp))
        {
            if (members.Count == 1)
            {
                rows[members[0]].GroupLabel = "Uncorrelated";
                continue;
            }

            groupNumber++;
            string reason = DescribeDominantMatchType(matchTypesByRoot.GetValueOrDefault(root));
            string label = $"Group {groupNumber} — {reason}";
            foreach (int i in members)
                rows[i].GroupLabel = label;
        }
    }

    private static string DescribeDominantMatchType(List<CorrelationMatchType>? types)
    {
        if (types is null || types.Count == 0)
            return "linked events";

        var dominant = types.GroupBy(t => t).OrderByDescending(g => g.Count()).First().Key;
        return dominant switch
        {
            CorrelationMatchType.SameLogonId => "same logon session",
            CorrelationMatchType.SameProcessId => "same process",
            CorrelationMatchType.SameInterfaceGuid => "same network adapter",
            CorrelationMatchType.TimeProximity => "occurred close together in time",
            _ => "linked events",
        };
    }
}
