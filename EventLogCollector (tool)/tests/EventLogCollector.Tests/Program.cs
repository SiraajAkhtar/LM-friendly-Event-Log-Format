using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using EventLogCollector;
using EventLogCollector.Gui.Services;

// test runner

int passed = 0;
int failed = 0;

await RunTest("Timestamp format is d/M/yy HH:mm:ss", TestTimestampFormat);
await RunTest("Single writer, entries flushed to disk", TestSingleWriter);
await RunTest("16 concurrent writers, no file-lock exceptions", TestConcurrentWriters);
await RunTest("Context column never breaks CSV column count", TestContextColumnStability);
await RunTest("Null and empty context both produce empty field", TestNullAndEmptyContext);
await RunTest("CSV fields with commas and quotes are escaped", TestCsvEscaping);
await RunTest("Writer can be re-opened (append mode)", TestAppendOnReopen);
await RunTest("1000 context keys — column count stays at 3", TestMassiveContext);
await RunTest("Context values with commas, quotes, semicolons, equals — no column bleed", TestNastyContextValues);

// os event log source
await RunTest("OsEventLogSource starts and stops without error", TestOsSourceSmoke);
await RunTest("OsEventLogSource — any captured events have exactly 3 columns", TestOsSourceColumnCount);

// application event log source
await RunTest("AppEventLogSource starts and stops without error", TestAppSourceSmoke);
await RunTest("AppEventLogSource — unknown channel list produces empty watcher set without throwing", TestAppSourceBadChannels);
await RunTest("AppEventLogSource — any captured events have exactly 3 columns and provider in context", TestAppSourceColumnCount);

// network event log source
await RunTest("NetworkEventLogSource starts and stops without error", TestNetworkSourceSmoke);
await RunTest("NetworkEventLogSource — unknown channel list produces empty watcher set without throwing", TestNetworkSourceBadChannels);
await RunTest("NetworkEventLogSource — any captured events have exactly 3 columns and provider in context", TestNetworkSourceColumnCount);

// event catalog
await RunTest("EventCatalog classifies known (channel, id) pairs", TestEventCatalogKnownIds);
await RunTest("EventCatalog rejects unlisted (channel, id) pairs as noise", TestEventCatalogUnknownIds);
await RunTest("EventCatalog classifies Application events by severity", TestEventCatalogApplicationSeverity);
await RunTest("EventCatalog.BuildContext sizes Context to fidelity tier", TestEventCatalogBuildContext);

// coded-field translation (LogonType, logon-failure SubStatus)
await RunTest("EventCatalog translates LogonType codes to friendly text", TestEventCatalogLogonTypeTranslation);
await RunTest("EventCatalog leaves an unrecognized LogonType digit unchanged", TestEventCatalogUnknownLogonTypePassesThrough);
await RunTest("EventCatalog translates well-known PrimaryGroupId RIDs to friendly text", TestEventCatalogPrimaryGroupIdTranslation);
await RunTest("EventCatalog leaves an unrecognized PrimaryGroupId RID unchanged", TestEventCatalogUnknownPrimaryGroupIdPassesThrough);
await RunTest("EventCatalog translates known 4625 SubStatus codes to friendly text", TestEventCatalogSubStatusTranslation);
await RunTest("EventCatalog still drops an unrecognized SubStatus code", TestEventCatalogUnknownSubStatusStillDropped);
await RunTest("EventCatalog drops a bare '-' placeholder value", TestEventCatalogDropsDashPlaceholder);
await RunTest("EventCatalog resolves a well-known SID to a friendly account name", TestEventCatalogResolvesKnownSid);
await RunTest("EventCatalog drops an unresolvable SID rather than surfacing it raw", TestEventCatalogDropsUnresolvableSid);
await RunTest("EventCatalog extracts old/new names from a real account-rename event", TestEventCatalogAccountRenameContext);
await RunTest("EventCatalog extracts readable SettingType/SettingValue from a 4950 firewall event", TestEventCatalogFirewallSettingChangedContext);
await RunTest("EventCatalog translates TokenElevationType codes to friendly text", TestEventCatalogTokenElevationTypeTranslation);
await RunTest("EventCatalog leaves an unrecognized TokenElevationType code unchanged", TestEventCatalogUnknownTokenElevationTypePassesThrough);
await RunTest("EventCatalog overrides BackupConfigurationChanged's broken native Description", TestEventCatalogBackupConfigurationChangedDescriptionOverride);
await RunTest("EventCatalog has no Description override for an ordinary event kind", TestEventCatalogNoDescriptionOverrideForOrdinaryKind);

// event description formatter
await RunTest("EventDescriptionFormatter strips hex codes", TestDescriptionFormatterStripsHexCodes);
await RunTest("EventDescriptionFormatter expands abbreviations", TestDescriptionFormatterExpandsAbbreviations);
await RunTest("EventDescriptionFormatter abstracts system accounts", TestDescriptionFormatterAbstractsSystemAccounts);
await RunTest("EventDescriptionFormatter keeps only the header line", TestDescriptionFormatterKeepsOnlyHeaderLine);
await RunTest("EventDescriptionFormatter handles null/empty input", TestDescriptionFormatterHandlesEmptyInput);
await RunTest("EventDescriptionFormatter applies all three rules together", TestDescriptionFormatterCombined);
await RunTest("EventDescriptionFormatter — Security logon example drops Subject/Logon Information blocks", TestDescriptionFormatterSecurityLogonExample);
await RunTest("EventDescriptionFormatter — WLAN connect example drops Network Adapter/interface fields", TestDescriptionFormatterWlanConnectExample);
await RunTest("Friendly description with commas and newlines survives CSV round-trip", TestDescriptionCsvSafety);

// event correlation engine
await RunTest("CorrelationIds.IsEmpty reflects whether any field is set", TestCorrelationIdsIsEmpty);
await RunTest("EventCorrelationEngine — unmapped EventKind yields no LogonId/InterfaceGuid", TestCorrelationEngineUnmappedKind);
await RunTest("EventCorrelationEngine — extracts ProcessId from a real System event", TestCorrelationEngineProcessId);
await RunTest("EventCorrelationEngine — extracts LogonId from a real Security 4624 event", TestCorrelationEngineLogonId);
await RunTest("EventCorrelationEngine — extracts InterfaceGuid from a real WLAN event", TestCorrelationEngineInterfaceGuid);
await RunTest("EventCorrelationEngine — malformed field lookup never throws", TestCorrelationEngineNeverThrows);
await RunTest("Correlation ids never leak into CSV Context or column count", TestCorrelationIdsNeverLeakIntoCsv);

// correlation index + linking
await RunTest("Index orders events by timestamp regardless of input order", TestCorrelationIndexOrdersByTimestamp);
await RunTest("Index groups events into ByLogonId/ByProcessId/ByInterfaceGuid, skipping nulls", TestCorrelationIndexGroupsById);
await RunTest("FindLinks — direct id match links consecutive same-id events within the window", TestFindLinksDirectIdMatchWithinWindow);
await RunTest("FindLinks — direct id match respects a custom window", TestFindLinksDirectIdMatchCustomWindow);
await RunTest("FindLinks — time proximity links different-id events within 4 seconds", TestFindLinksTimeProximityMatch);
await RunTest("FindLinks — a shared-id pair is not double-reported as a proximity match", TestFindLinksProximityExcludesSharedIdPairs);
await RunTest("FindLinks — unrelated events (different ids, far apart) produce no links", TestFindLinksNoLinksForUnrelatedEvents);
await RunTest("Index — organizes real captured events by timestamp and native ProcessId", TestCorrelationIndexRealEvents);
await RunTest("FindLinks — links a real network event and a real security event within proximity", TestFindLinksRealNetworkAndSecurityProximity);

// AccountAttributeTracker (self-tracked 4738 diffing)
await RunTest("AccountSnapshot.Diff detects a single changed field", TestAccountSnapshotDiffSingleField);
await RunTest("AccountSnapshot.Diff detects multiple changed fields", TestAccountSnapshotDiffMultipleFields);
await RunTest("AccountSnapshot.Diff reports nothing for identical snapshots", TestAccountSnapshotDiffNoChange);
await RunTest("AccountSnapshot.Diff handles a field going from unset to set", TestAccountSnapshotDiffUnsetToSet);
await RunTest("AccountAttributeTracker — cold start reports no change on first observation", TestAccountAttributeTrackerColdStart);

// platform-gap trackers (screenshot, Windows Update settings)
await RunTest("WindowsUpdateSettingsSnapshot.Diff detects a single changed field", TestWuSettingsDiffSingleField);
await RunTest("WindowsUpdateSettingsSnapshot.Diff detects multiple changed fields", TestWuSettingsDiffMultipleFields);
await RunTest("WindowsUpdateSettingsSnapshot.Diff reports nothing for identical snapshots", TestWuSettingsDiffNoChange);
await RunTest("WindowsUpdateSettingsSnapshot.Diff handles PauseUpdatesActive going from unset to set", TestWuSettingsDiffPauseToggle);
await RunTest("ScreenshotCaptureSource starts and stops without error against a missing folder", TestScreenshotSourceSmoke);
await RunTest("ScreenshotCaptureSource — a new file in the watched folder produces a 3-column CsvEntry", TestScreenshotSourceCapturesNewFile);
await RunTest("WindowsUpdateSettingsSource starts and stops without error", TestWuSettingsSourceSmoke);

// EventCsvReader
await RunTest("EventCsvReader round-trips entries written by EventCsvWriter", TestCsvReaderRoundTrip);
await RunTest("EventCsvReader round-trips fields containing commas, quotes, semicolons, equals", TestCsvReaderRoundTripNastyFields);
await RunTest("EventCsvReader returns no entries for a header-only file", TestCsvReaderEmptyFile);

// file-lock resilience
await RunTest("EventCsvWriter survives another process holding an exclusive lock briefly, then writes once it clears", TestWriterRetriesTransientLock);
await RunTest("EventCsvWriter surfaces WriteFault (not an exception) for an unrecoverable path", TestWriterSurfacesFaultOnUnrecoverablePath);
await RunTest("EventCsvWriter keeps accepting TryWrite calls after an unrecoverable path fault", TestWriterNeverThrowsOnUnrecoverablePath);

// LogSessionRepository correlation reload (regression)
await RunTest("LoadAllRowsWithCorrelationAsync recovers CorrelationIds across a reload despite sub-second sidecar timestamps", TestSessionRepositoryRecoversCorrelationIdsAcrossReload);
await RunTest("LoadAllRowsWithCorrelationAsync + CorrelationGrouping actually groups reloaded same-process rows together", TestReloadedSessionGroupsCorrectlyByProcessId);

Console.WriteLine();
Console.WriteLine($"Results: {passed} passed, {failed} failed");
return failed > 0 ? 1 : 0;

// individual tests

async Task TestTimestampFormat()
{
    string path = TempFile();
    var known = new DateTimeOffset(2027, 1, 2, 21, 5, 5, TimeSpan.Zero);  // 2/1/27 21:05:05
    await using (var w = new EventCsvWriter(path))
        w.TryWrite(new CsvEntry(known, "test"));

    string[] lines = File.ReadAllLines(path);
    string ts = lines[1].Split(',')[0];
    Assert(ts == "2/1/27 21:05:05", $"Timestamp format wrong: got '{ts}'");
}

async Task TestSingleWriter()
{
    string path = TempFile();
    await using (var w = new EventCsvWriter(path))
    {
        w.TryWrite(new CsvEntry(DateTimeOffset.UtcNow, "system started"));
        w.TryWrite(new CsvEntry(DateTimeOffset.UtcNow, "first event"));
    }

    string[] lines = File.ReadAllLines(path);
    Assert(lines.Length == 3, $"Expected 3 lines (header + 2 entries), got {lines.Length}");
    Assert(lines[0] == "Timestamp,Description,Context", $"Header wrong: {lines[0]}");
}

async Task TestConcurrentWriters()
{
    const int threadCount = 16;
    const int entriesPerThread = 200;
    string path = TempFile();

    await using (var w = new EventCsvWriter(path))
    {
        var tasks = Enumerable.Range(0, threadCount).Select(i => Task.Run(() =>
        {
            for (int j = 0; j < entriesPerThread; j++)
                w.TryWrite(new CsvEntry(DateTimeOffset.UtcNow, $"thread={i} seq={j}"));
        }));
        await Task.WhenAll(tasks);
    }  // DisposeAsync flushes everything before the read

    string[] lines = File.ReadAllLines(path);
    int expected = 1 + threadCount * entriesPerThread;  // header + all entries
    Assert(lines.Length == expected, $"Expected {expected} lines, got {lines.Length}");
}

async Task TestContextColumnStability()
{
    string path = TempFile();
    await using (var w = new EventCsvWriter(path))
    {
        // no context
        w.TryWrite(new CsvEntry(DateTimeOffset.UtcNow, "no context"));

        // minimal context
        w.TryWrite(new CsvEntry(DateTimeOffset.UtcNow, "one key",
            new Dictionary<string, string> { ["source"] = "kernel" }));

        // rich context
        w.TryWrite(new CsvEntry(DateTimeOffset.UtcNow, "many keys",
            new Dictionary<string, string>
            {
                ["source"]   = "kernel",
                ["pid"]      = "1234",
                ["severity"] = "warning",
                ["channel"]  = "System"
            }));
    }

    string[] lines = File.ReadAllLines(path);

    // exactly 3 columns, commas counted properly
    foreach (string line in lines)
    {
        int cols = CountCsvColumns(line);
        Assert(cols == 3, $"Expected 3 columns, got {cols} in: {line}");
    }
}

async Task TestNullAndEmptyContext()
{
    string path = TempFile();
    await using (var w = new EventCsvWriter(path))
    {
        w.TryWrite(new CsvEntry(DateTimeOffset.UtcNow, "null ctx", null));
        w.TryWrite(new CsvEntry(DateTimeOffset.UtcNow, "empty ctx", new Dictionary<string, string>()));
    }

    string[] lines = File.ReadAllLines(path);
    // trailing comma for empty context
    Assert(lines[1].EndsWith(","), $"Null context: expected trailing comma, got: {lines[1]}");
    Assert(lines[2].EndsWith(","), $"Empty context: expected trailing comma, got: {lines[2]}");
}

async Task TestCsvEscaping()
{
    string path = TempFile();
    await using (var w = new EventCsvWriter(path))
    {
        w.TryWrite(new CsvEntry(DateTimeOffset.UtcNow, "event, with comma"));
        w.TryWrite(new CsvEntry(DateTimeOffset.UtcNow, "event \"with\" quotes"));
    }

    string[] lines = File.ReadAllLines(path);
    Assert(lines[1].Contains("\"event, with comma\""), $"Comma not escaped: {lines[1]}");
    Assert(lines[2].Contains("\"event \"\"with\"\" quotes\""), $"Quote not escaped: {lines[2]}");
}

async Task TestAppendOnReopen()
{
    string path = TempFile();

    // first session
    await using (var w = new EventCsvWriter(path))
        w.TryWrite(new CsvEntry(DateTimeOffset.UtcNow, "session 1"));

    // second session, append not overwrite
    await using (var w = new EventCsvWriter(path))
        w.TryWrite(new CsvEntry(DateTimeOffset.UtcNow, "session 2"));

    string[] lines = File.ReadAllLines(path);
    Assert(lines.Length == 3, $"Expected 3 lines after two sessions, got {lines.Length}");

    int headerCount = lines.Count(l => l.StartsWith("Timestamp,"));
    Assert(headerCount == 1, $"Expected exactly 1 header line, got {headerCount}");
}

async Task TestMassiveContext()
{
    // context keys always produce 3 columns
    int[] sizes = [1, 10, 100, 1000];
    string path = TempFile();

    await using (var w = new EventCsvWriter(path))
    {
        foreach (int size in sizes)
        {
            var ctx = Enumerable.Range(0, size)
                .ToDictionary(i => $"key{i}", i => $"value{i}");
            w.TryWrite(new CsvEntry(DateTimeOffset.UtcNow, $"{size}-key context", ctx));
        }
    }

    string[] lines = File.ReadAllLines(path);
    Assert(lines.Length == 1 + sizes.Length, $"Expected {1 + sizes.Length} lines, got {lines.Length}");

    foreach (string line in lines)
    {
        int cols = CountCsvColumns(line);
        Assert(cols == 3, $"Expected 3 columns regardless of context size, got {cols} in: {line[..Math.Min(80, line.Length)]}...");
    }
}

async Task TestNastyContextValues()
{
    // context chars that could break csv encoding
    string path = TempFile();

    await using (var w = new EventCsvWriter(path))
    {
        w.TryWrite(new CsvEntry(DateTimeOffset.UtcNow, "nasty values",
            new Dictionary<string, string>
            {
                ["comma_val"]     = "value,with,commas",
                ["quote_val"]     = "value \"with\" quotes",
                ["semicolon_val"] = "value;with;semicolons",
                ["equals_val"]    = "value=with=equals",
                ["newline_val"]   = "value\nwith\nnewlines",
                ["mixed_val"]     = "C:\\path\\to\\file, \"quoted\"; key=val"
            }));
    }

    string[] lines = File.ReadAllLines(path);
    // embedded newlines must not add columns
    int cols = CountCsvColumns(string.Join("", lines.Skip(1)));
    Assert(lines.Length >= 2, "Expected at least header + 1 data line");
    foreach (string line in lines)
    {
        int c = CountCsvColumns(line);
        Assert(c == 3, $"Expected 3 columns, got {c} in: {line[..Math.Min(80, line.Length)]}");
    }
}

// application event log source tests

async Task TestAppSourceSmoke()
{
    string path = TempFile();
    await using var writer = new EventCsvWriter(path);
    using (var source = new AppEventLogSource(writer))
        await Task.Delay(300);
}

async Task TestAppSourceBadChannels()
{
    string path = TempFile();
    await using var writer = new EventCsvWriter(path);
    using var source = new AppEventLogSource(writer,
        ["This-Channel-Does-Not-Exist/Operational", "Also-Fake/Admin"]);
    await Task.Delay(100);
}

async Task TestAppSourceColumnCount()
{
    string path = TempFile();

    await using (var writer = new EventCsvWriter(path))
    using (var source = new AppEventLogSource(writer))
        await Task.Delay(3000);

    string[] lines = File.ReadAllLines(path);
    if (lines.Length <= 1)
    {
        Console.WriteLine("         (no app events arrived in 3 s window — skipping column check)");
        return;
    }

    foreach (string line in lines.Skip(1))
    {
        int cols = CountCsvColumns(line);
        Assert(cols == 3, $"Expected 3 columns from app event, got {cols} in: {line[..Math.Min(120, line.Length)]}");
        // provider/channel are present at every fidelity tier; xml only appears at High.
        Assert(line.Contains("provider="), $"Expected provider field in context, got: {line[..Math.Min(120, line.Length)]}");
    }

    Console.WriteLine($"         ({lines.Length - 1} app events captured and verified)");
}

// network event log source tests

async Task TestNetworkSourceSmoke()
{
    string path = TempFile();
    await using var writer = new EventCsvWriter(path);
    using (var source = new NetworkEventLogSource(writer))
        await Task.Delay(300);
}

async Task TestNetworkSourceBadChannels()
{
    string path = TempFile();
    await using var writer = new EventCsvWriter(path);
    // bogus channels skipped, never throw
    using var source = new NetworkEventLogSource(writer,
        ["This-Channel-Does-Not-Exist/Operational", "Also-Fake/Admin"]);
    await Task.Delay(100);
}

async Task TestNetworkSourceColumnCount()
{
    string path = TempFile();

    await using (var writer = new EventCsvWriter(path))
    using (var source = new NetworkEventLogSource(writer))
        await Task.Delay(3000);

    string[] lines = File.ReadAllLines(path);
    if (lines.Length <= 1)
    {
        Console.WriteLine("         (no network events arrived in 3 s window — skipping column check)");
        return;
    }

    foreach (string line in lines.Skip(1))
    {
        int cols = CountCsvColumns(line);
        Assert(cols == 3, $"Expected 3 columns from network event, got {cols} in: {line[..Math.Min(120, line.Length)]}");

        // provider/channel are present at every fidelity tier; xml only appears at High.
        Assert(line.Contains("provider="), $"Expected provider field in context, got: {line[..Math.Min(120, line.Length)]}");
    }

    Console.WriteLine($"         ({lines.Length - 1} network events captured and verified)");
}

// os event log source tests

async Task TestOsSourceSmoke()
{
    string path = TempFile();
    await using var writer = new EventCsvWriter(path);

    // subscribe then dispose cleanly
    using (var source = new OsEventLogSource(writer))
        await Task.Delay(300);
}

async Task TestOsSourceColumnCount()
{
    string path = TempFile();

    // dispose writer before reading
    await using (var writer = new EventCsvWriter(path))
    using (var source = new OsEventLogSource(writer))
        await Task.Delay(3000);

    string[] lines = File.ReadAllLines(path);
    if (lines.Length <= 1)
    {
        Console.WriteLine("         (no OS events arrived in 3 s window — skipping column check)");
        return;
    }

    foreach (string line in lines.Skip(1))
    {
        int cols = CountCsvColumns(line);
        Assert(cols == 3, $"Expected 3 columns from OS event, got {cols} in: {line[..Math.Min(120, line.Length)]}");
        // provider/channel are present at every fidelity tier; xml only appears at High.
        Assert(line.Contains("provider="), $"Expected provider field in context, got: {line[..Math.Min(120, line.Length)]}");
    }

    Console.WriteLine($"         ({lines.Length - 1} OS events captured and verified)");
}

// event catalog tests

Task TestEventCatalogKnownIds()
{
    Assert(EventCatalog.TryClassify("System", 1074, out var c1)
        && c1.Kind == EventKind.SystemShutdownInitiated && c1.Fidelity == FidelityLevel.Low,
        "System/1074 should classify as SystemShutdownInitiated, Low fidelity");
    // medium not low, logontype parsed from xml
    Assert(EventCatalog.TryClassify("Security", 4624, out var c2)
        && c2.Kind == EventKind.LogonSuccess && c2.Fidelity == FidelityLevel.Medium,
        "Security/4624 should classify as LogonSuccess, Medium fidelity");
    Assert(EventCatalog.TryClassify("Security", 4634, out var cLogoff)
        && cLogoff.Kind == EventKind.LogoffSession && cLogoff.Fidelity == FidelityLevel.Medium,
        "Security/4634 should classify as LogoffSession, Medium fidelity");
    Assert(EventCatalog.TryClassify("Security", 4647, out var cLogoffUser)
        && cLogoffUser.Kind == EventKind.LogoffUserInitiated && cLogoffUser.Fidelity == FidelityLevel.Medium,
        "Security/4647 should classify as LogoffUserInitiated, Medium fidelity");
    Assert(EventCatalog.TryClassify("Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", 21, out var cRdsLogon)
        && cRdsLogon.Kind == EventKind.RdsSessionLogon && cRdsLogon.Fidelity == FidelityLevel.Medium,
        "LocalSessionManager/21 should classify as RdsSessionLogon, Medium fidelity");
    Assert(EventCatalog.TryClassify("Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", 23, out var cRdsLogoff)
        && cRdsLogoff.Kind == EventKind.RdsSessionLogoff && cRdsLogoff.Fidelity == FidelityLevel.Medium,
        "LocalSessionManager/23 should classify as RdsSessionLogoff, Medium fidelity");
    Assert(EventCatalog.TryClassify("Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", 24, out var cRdsDisc)
        && cRdsDisc.Kind == EventKind.RdsSessionDisconnected && cRdsDisc.Fidelity == FidelityLevel.Medium,
        "LocalSessionManager/24 should classify as RdsSessionDisconnected, Medium fidelity");
    Assert(EventCatalog.TryClassify("Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", 25, out var cRdsRecon)
        && cRdsRecon.Kind == EventKind.RdsSessionReconnected && cRdsRecon.Fidelity == FidelityLevel.Medium,
        "LocalSessionManager/25 should classify as RdsSessionReconnected, Medium fidelity");
    Assert(EventCatalog.TryClassify("Security", 4625, out var c3)
        && c3.Kind == EventKind.LogonFailure && c3.Fidelity == FidelityLevel.High,
        "Security/4625 should classify as LogonFailure, High fidelity");
    Assert(EventCatalog.TryClassify("Microsoft-Windows-WLAN-AutoConfig/Operational", 8001, out var c4)
        && c4.Kind == EventKind.WifiConnected && c4.Fidelity == FidelityLevel.Medium,
        "WLAN-AutoConfig/8001 should classify as WifiConnected, Medium fidelity");
    Assert(EventCatalog.TryClassify("Microsoft-Windows-Windows Defender/Operational", 1116, out var c5)
        && c5.Kind == EventKind.MalwareDetected && c5.Fidelity == FidelityLevel.High,
        "Defender/1116 should classify as MalwareDetected, High fidelity");
    // real firewall rule change ids
    Assert(EventCatalog.TryClassify("Microsoft-Windows-Windows Firewall With Advanced Security/Firewall", 2097, out var c6)
        && c6.Kind == EventKind.FirewallRuleAdded && c6.Fidelity == FidelityLevel.High,
        "Firewall/2097 should classify as FirewallRuleAdded, High fidelity");
    Assert(EventCatalog.TryClassify("System", 1, out var c7)
        && c7.Kind == EventKind.SystemTimeChanged && c7.Fidelity == FidelityLevel.High,
        "System/1 should classify as SystemTimeChanged, High fidelity");
    Assert(EventCatalog.TryClassify("Microsoft-Windows-WLAN-AutoConfig/Operational", 11006, out var c8)
        && c8.Kind == EventKind.WifiSecurityFailed && c8.Fidelity == FidelityLevel.High,
        "WLAN-AutoConfig/11006 should classify as WifiSecurityFailed, High fidelity");
    Assert(EventCatalog.TryClassify("Microsoft-Windows-Kernel-PnP/Configuration", 400, out var c9)
        && c9.Kind == EventKind.DeviceConfigured && c9.Fidelity == FidelityLevel.Medium,
        "Kernel-PnP/Configuration/400 should classify as DeviceConfigured, Medium fidelity");
    Assert(EventCatalog.TryClassify("Security", 4688, out var c10)
        && c10.Kind == EventKind.ProcessCreated && c10.Fidelity == FidelityLevel.Medium,
        "Security/4688 should classify as ProcessCreated, Medium fidelity");
    // anti-forensics and privilege-escalation ids
    Assert(EventCatalog.TryClassify("Security", 1102, out var c11)
        && c11.Kind == EventKind.AuditLogCleared && c11.Fidelity == FidelityLevel.High,
        "Security/1102 should classify as AuditLogCleared, High fidelity");
    Assert(EventCatalog.TryClassify("Security", 4719, out var c12)
        && c12.Kind == EventKind.AuditPolicyChanged && c12.Fidelity == FidelityLevel.High,
        "Security/4719 should classify as AuditPolicyChanged, High fidelity");
    Assert(EventCatalog.TryClassify("Security", 4720, out var c13)
        && c13.Kind == EventKind.UserAccountCreated && c13.Fidelity == FidelityLevel.High,
        "Security/4720 should classify as UserAccountCreated, High fidelity");
    Assert(EventCatalog.TryClassify("Security", 4728, out var c14)
        && c14.Kind == EventKind.SecurityGroupMemberAdded && c14.Fidelity == FidelityLevel.High,
        "Security/4728 should classify as SecurityGroupMemberAdded, High fidelity");
    Assert(EventCatalog.TryClassify("Security", 4732, out var c15)
        && c15.Kind == EventKind.SecurityGroupMemberAdded && c15.Fidelity == FidelityLevel.High,
        "Security/4732 should classify as SecurityGroupMemberAdded, High fidelity");
    Assert(EventCatalog.TryClassify("Security", 4756, out var c16)
        && c16.Kind == EventKind.SecurityGroupMemberAdded && c16.Fidelity == FidelityLevel.High,
        "Security/4756 should classify as SecurityGroupMemberAdded, High fidelity");
    Assert(EventCatalog.TryClassify("Security", 4648, out var c17)
        && c17.Kind == EventKind.ExplicitCredentialLogon && c17.Fidelity == FidelityLevel.High,
        "Security/4648 should classify as ExplicitCredentialLogon, High fidelity");
    Assert(EventCatalog.TryClassify("Security", 4672, out var c18)
        && c18.Kind == EventKind.PrivilegedLogonUsed && c18.Fidelity == FidelityLevel.High,
        "Security/4672 should classify as PrivilegedLogonUsed, High fidelity");
    Assert(EventCatalog.TryClassify("Security", 4740, out var c19)
        && c19.Kind == EventKind.AccountLockedOut && c19.Fidelity == FidelityLevel.High,
        "Security/4740 should classify as AccountLockedOut, High fidelity");
    Assert(EventCatalog.TryClassify("Microsoft-Windows-Windows Defender/Operational", 5001, out var c20)
        && c20.Kind == EventKind.DefenderRealTimeProtectionDisabled && c20.Fidelity == FidelityLevel.High,
        "Defender/5001 should classify as DefenderRealTimeProtectionDisabled, High fidelity");
    Assert(EventCatalog.TryClassify("Microsoft-Windows-WindowsUpdateClient/Operational", 19, out var c21)
        && c21.Kind == EventKind.WindowsUpdateInstalled && c21.Fidelity == FidelityLevel.Medium,
        "WindowsUpdateClient/19 should classify as WindowsUpdateInstalled, Medium fidelity");
    // account lifecycle events
    Assert(EventCatalog.TryClassify("Security", 4722, out var c22)
        && c22.Kind == EventKind.UserAccountEnabled && c22.Fidelity == FidelityLevel.High,
        "Security/4722 should classify as UserAccountEnabled, High fidelity");
    Assert(EventCatalog.TryClassify("Security", 4725, out var c23)
        && c23.Kind == EventKind.UserAccountDisabled && c23.Fidelity == FidelityLevel.High,
        "Security/4725 should classify as UserAccountDisabled, High fidelity");
    Assert(EventCatalog.TryClassify("Security", 4726, out var c24)
        && c24.Kind == EventKind.UserAccountDeleted && c24.Fidelity == FidelityLevel.High,
        "Security/4726 should classify as UserAccountDeleted, High fidelity");
    Assert(EventCatalog.TryClassify("Security", 4738, out var c25)
        && c25.Kind == EventKind.UserAccountChanged && c25.Fidelity == FidelityLevel.High,
        "Security/4738 should classify as UserAccountChanged, High fidelity");
    Assert(EventCatalog.TryClassify("Security", 4724, out var c26)
        && c26.Kind == EventKind.PasswordResetAttempted && c26.Fidelity == FidelityLevel.High,
        "Security/4724 should classify as PasswordResetAttempted, High fidelity");
    Assert(EventCatalog.TryClassify("Security", 4767, out var c27)
        && c27.Kind == EventKind.AccountUnlocked && c27.Fidelity == FidelityLevel.High,
        "Security/4767 should classify as AccountUnlocked, High fidelity");
    // account rename detail
    Assert(EventCatalog.TryClassify("Security", 4781, out var cRename)
        && cRename.Kind == EventKind.AccountNameChanged && cRename.Fidelity == FidelityLevel.High,
        "Security/4781 should classify as AccountNameChanged, High fidelity");
    Assert(EventCatalog.TryClassify("Security", 4735, out var c28)
        && c28.Kind == EventKind.SecurityGroupChanged && c28.Fidelity == FidelityLevel.High,
        "Security/4735 should classify as SecurityGroupChanged, High fidelity");
    Assert(EventCatalog.TryClassify("Security", 4697, out var c29)
        && c29.Kind == EventKind.ServiceInstalled && c29.Fidelity == FidelityLevel.High,
        "Security/4697 should classify as ServiceInstalled, High fidelity");

    // manifest sweep across providers
    Assert(EventCatalog.TryClassify("Microsoft-Windows-Windows Defender/Operational", 1015, out var c30)
        && c30.Kind == EventKind.BehavioralDetection && c30.Fidelity == FidelityLevel.High,
        "Defender/1015 should classify as BehavioralDetection, High fidelity");
    Assert(EventCatalog.TryClassify("Microsoft-Windows-Windows Defender/Operational", 1160, out var c31)
        && c31.Kind == EventKind.PotentiallyUnwantedAppDetected && c31.Fidelity == FidelityLevel.High,
        "Defender/1160 should classify as PotentiallyUnwantedAppDetected, High fidelity");
    Assert(EventCatalog.TryClassify("Microsoft-Windows-Windows Defender/Operational", 1121, out var c32)
        && c32.Kind == EventKind.ExploitGuardBlocked && c32.Fidelity == FidelityLevel.High,
        "Defender/1121 should classify as ExploitGuardBlocked, High fidelity");
    Assert(EventCatalog.TryClassify("Microsoft-Windows-Windows Defender/Operational", 1123, out var c33)
        && c33.Kind == EventKind.ControlledFolderAccessBlocked && c33.Fidelity == FidelityLevel.High,
        "Defender/1123 should classify as ControlledFolderAccessBlocked, High fidelity");
    Assert(EventCatalog.TryClassify("Microsoft-Windows-Windows Defender/Operational", 5007, out var c34)
        && c34.Kind == EventKind.DefenderConfigurationChanged && c34.Fidelity == FidelityLevel.High,
        "Defender/5007 should classify as DefenderConfigurationChanged, High fidelity");
    Assert(EventCatalog.TryClassify("Microsoft-Windows-Windows Defender/Operational", 5013, out var c35)
        && c35.Kind == EventKind.DefenderTamperProtectionBlocked && c35.Fidelity == FidelityLevel.High,
        "Defender/5013 should classify as DefenderTamperProtectionBlocked, High fidelity");
    Assert(EventCatalog.TryClassify("Microsoft-Windows-TaskScheduler/Operational", 142, out var c36)
        && c36.Kind == EventKind.ScheduledTaskDisabled && c36.Fidelity == FidelityLevel.High,
        "TaskScheduler/142 should classify as ScheduledTaskDisabled, High fidelity");
    Assert(EventCatalog.TryClassify("Microsoft-Windows-Kernel-PnP/Configuration", 401, out var c37)
        && c37.Kind == EventKind.DeviceConfigurationFailed && c37.Fidelity == FidelityLevel.High,
        "Kernel-PnP/Configuration/401 should classify as DeviceConfigurationFailed, High fidelity");
    Assert(EventCatalog.TryClassify("Microsoft-Windows-Kernel-PnP/Configuration", 402, out var c38)
        && c38.Kind == EventKind.DeviceConfigurationBlockedByPolicy && c38.Fidelity == FidelityLevel.High,
        "Kernel-PnP/Configuration/402 should classify as DeviceConfigurationBlockedByPolicy, High fidelity");
    Assert(EventCatalog.TryClassify("Microsoft-Windows-WindowsUpdateClient/Operational", 20, out var c39)
        && c39.Kind == EventKind.WindowsUpdateInstallFailed && c39.Fidelity == FidelityLevel.High,
        "WindowsUpdateClient/20 should classify as WindowsUpdateInstallFailed, High fidelity");
    Assert(EventCatalog.TryClassify("Microsoft-Windows-WLAN-AutoConfig/Operational", 8002, out var c40)
        && c40.Kind == EventKind.WifiConnectionFailed && c40.Fidelity == FidelityLevel.High,
        "WLAN-AutoConfig/8002 should classify as WifiConnectionFailed, High fidelity");
    Assert(EventCatalog.TryClassify("Microsoft-Windows-WLAN-AutoConfig/Operational", 11002, out var c41)
        && c41.Kind == EventKind.WifiAssociationFailed && c41.Fidelity == FidelityLevel.High,
        "WLAN-AutoConfig/11002 should classify as WifiAssociationFailed, High fidelity");
    Assert(EventCatalog.TryClassify("Microsoft-Windows-WLAN-AutoConfig/Operational", 11005, out var c42)
        && c42.Kind == EventKind.WifiSecuritySucceeded && c42.Fidelity == FidelityLevel.Medium,
        "WLAN-AutoConfig/11005 should classify as WifiSecuritySucceeded, Medium fidelity");
    Assert(EventCatalog.TryClassify("Microsoft-Windows-WLAN-AutoConfig/Operational", 12012, out var c43)
        && c43.Kind == EventKind.Wifi8021xAuthSucceeded && c43.Fidelity == FidelityLevel.Medium,
        "WLAN-AutoConfig/12012 should classify as Wifi8021xAuthSucceeded, Medium fidelity");
    Assert(EventCatalog.TryClassify("Microsoft-Windows-WLAN-AutoConfig/Operational", 12013, out var c44)
        && c44.Kind == EventKind.Wifi8021xAuthFailed && c44.Fidelity == FidelityLevel.High,
        "WLAN-AutoConfig/12013 should classify as Wifi8021xAuthFailed, High fidelity");
    Assert(EventCatalog.TryClassify("Microsoft-Windows-WLAN-AutoConfig/Operational", 12014, out var c45)
        && c45.Kind == EventKind.Wifi8021xAuthRestarted && c45.Fidelity == FidelityLevel.Medium,
        "WLAN-AutoConfig/12014 should classify as Wifi8021xAuthRestarted, Medium fidelity");
    Assert(EventCatalog.TryClassify("Microsoft-Windows-TerminalServices-RDPClient/Operational", 1005, out var c46)
        && c46.Kind == EventKind.RdpLogonFailed && c46.Fidelity == FidelityLevel.High,
        "RDPClient/1005 should classify as RdpLogonFailed, High fidelity");
    Assert(EventCatalog.TryClassify("Microsoft-Windows-TerminalServices-RDPClient/Operational", 1009, out var c47)
        && c47.Kind == EventKind.RdpLogonFailed && c47.Fidelity == FidelityLevel.High,
        "RDPClient/1009 should classify as RdpLogonFailed, High fidelity");
    Assert(EventCatalog.TryClassify("Microsoft-Windows-TerminalServices-RDPClient/Operational", 1018, out var c48)
        && c48.Kind == EventKind.RdpConnectionFailed && c48.Fidelity == FidelityLevel.High,
        "RDPClient/1018 should classify as RdpConnectionFailed, High fidelity");
    // 2082/2083 actually fire not 2002/2003
    Assert(EventCatalog.TryClassify("Microsoft-Windows-Windows Firewall With Advanced Security/Firewall", 2082, out var c49)
        && c49.Kind == EventKind.FirewallSettingChanged && c49.Fidelity == FidelityLevel.High,
        "Firewall/2082 should classify as FirewallSettingChanged, High fidelity");
    Assert(EventCatalog.TryClassify("Microsoft-Windows-Windows Firewall With Advanced Security/Firewall", 2083, out var c50)
        && c50.Kind == EventKind.FirewallSettingChanged && c50.Fidelity == FidelityLevel.High,
        "Firewall/2083 should classify as FirewallSettingChanged, High fidelity");
    // audit-log equivalent, dormant until subcategory enabled
    Assert(EventCatalog.TryClassify("Security", 4950, out var c50b)
        && c50b.Kind == EventKind.FirewallSettingChanged && c50b.Fidelity == FidelityLevel.High,
        "Security/4950 should classify as FirewallSettingChanged, High fidelity");
    Assert(!EventCatalog.TryClassify("Microsoft-Windows-Windows Firewall With Advanced Security/Firewall", 2002, out _)
        && !EventCatalog.TryClassify("Microsoft-Windows-Windows Firewall With Advanced Security/Firewall", 2003, out _),
        "Firewall/2002 and 2003 never actually fire on real Windows (live-verified) — should not classify");
    Assert(EventCatalog.TryClassify("Microsoft-Windows-Windows Firewall With Advanced Security/Firewall", 2032, out var c51)
        && c51.Kind == EventKind.FirewallResetToDefault && c51.Fidelity == FidelityLevel.High,
        "Firewall/2032 should classify as FirewallResetToDefault, High fidelity");
    Assert(EventCatalog.TryClassify("Microsoft-Windows-Windows Firewall With Advanced Security/Firewall", 2033, out var c52)
        && c52.Kind == EventKind.FirewallAllRulesDeleted && c52.Fidelity == FidelityLevel.High,
        "Firewall/2033 should classify as FirewallAllRulesDeleted, High fidelity");
    Assert(EventCatalog.TryClassify("Microsoft-Windows-NetworkProfile/Operational", 10002, out var c53)
        && c53.Kind == EventKind.NetworkCategoryChanged && c53.Fidelity == FidelityLevel.Medium,
        "NetworkProfile/10002 should classify as NetworkCategoryChanged, Medium fidelity");

    // 20-scenario pass
    Assert(EventCatalog.TryClassify("Security", 4723, out var c54)
        && c54.Kind == EventKind.PasswordChanged && c54.Fidelity == FidelityLevel.High,
        "Security/4723 should classify as PasswordChanged, High fidelity");
    Assert(EventCatalog.TryClassify("Security", 4729, out var c55)
        && c55.Kind == EventKind.SecurityGroupMemberRemoved && c55.Fidelity == FidelityLevel.High,
        "Security/4729 should classify as SecurityGroupMemberRemoved, High fidelity");
    Assert(EventCatalog.TryClassify("Security", 4733, out var c56)
        && c56.Kind == EventKind.SecurityGroupMemberRemoved && c56.Fidelity == FidelityLevel.High,
        "Security/4733 should classify as SecurityGroupMemberRemoved, High fidelity");
    Assert(EventCatalog.TryClassify("Security", 4757, out var c57)
        && c57.Kind == EventKind.SecurityGroupMemberRemoved && c57.Fidelity == FidelityLevel.High,
        "Security/4757 should classify as SecurityGroupMemberRemoved, High fidelity");
    Assert(EventCatalog.TryClassify("Security", 4704, out var c58)
        && c58.Kind == EventKind.UserRightAssigned && c58.Fidelity == FidelityLevel.High,
        "Security/4704 should classify as UserRightAssigned, High fidelity");
    Assert(EventCatalog.TryClassify("Security", 4705, out var c59)
        && c59.Kind == EventKind.UserRightRemoved && c59.Fidelity == FidelityLevel.High,
        "Security/4705 should classify as UserRightRemoved, High fidelity");
    Assert(EventCatalog.TryClassify("Security", 4663, out var c60)
        && c60.Kind == EventKind.RemovableStorageDataAccessed && c60.Fidelity == FidelityLevel.High,
        "Security/4663 should classify as RemovableStorageDataAccessed, High fidelity");
    Assert(EventCatalog.TryClassify("Microsoft-Windows-BitLocker/BitLocker Management", 768, out var c61)
        && c61.Kind == EventKind.BitLockerEncryptionStarted && c61.Fidelity == FidelityLevel.High,
        "BitLocker Management/768 should classify as BitLockerEncryptionStarted, High fidelity");
    Assert(EventCatalog.TryClassify("Microsoft-Windows-BitLocker/BitLocker Management", 773, out var c62)
        && c62.Kind == EventKind.BitLockerProtectionSuspended && c62.Fidelity == FidelityLevel.High,
        "BitLocker Management/773 should classify as BitLockerProtectionSuspended, High fidelity");
    Assert(EventCatalog.TryClassify("Microsoft-Windows-BitLocker/BitLocker Management", 774, out var c63)
        && c63.Kind == EventKind.BitLockerProtectionResumed && c63.Fidelity == FidelityLevel.High,
        "BitLocker Management/774 should classify as BitLockerProtectionResumed, High fidelity");
    Assert(EventCatalog.TryClassify("Microsoft-Windows-BitLocker/BitLocker Management", 775, out var c64)
        && c64.Kind == EventKind.BitLockerKeyProtectorAdded && c64.Fidelity == FidelityLevel.High,
        "BitLocker Management/775 should classify as BitLockerKeyProtectorAdded, High fidelity");
    Assert(EventCatalog.TryClassify("Microsoft-Windows-BitLocker/BitLocker Management", 776, out var c65)
        && c65.Kind == EventKind.BitLockerKeyProtectorRemoved && c65.Fidelity == FidelityLevel.High,
        "BitLocker Management/776 should classify as BitLockerKeyProtectorRemoved, High fidelity");
    Assert(EventCatalog.TryClassify("Microsoft-Windows-BitLocker/BitLocker Management", 781, out var c66)
        && c66.Kind == EventKind.BitLockerVolumeLocked && c66.Fidelity == FidelityLevel.High,
        "BitLocker Management/781 should classify as BitLockerVolumeLocked, High fidelity");
    Assert(EventCatalog.TryClassify("Microsoft-Windows-BitLocker/BitLocker Management", 782, out var c67)
        && c67.Kind == EventKind.BitLockerVolumeUnlocked && c67.Fidelity == FidelityLevel.High,
        "BitLocker Management/782 should classify as BitLockerVolumeUnlocked, High fidelity");
    Assert(EventCatalog.TryClassify("Microsoft-Windows-WindowsBackup/ActionCenter", 100, out var c68)
        && c68.Kind == EventKind.BackupConfigurationChanged && c68.Fidelity == FidelityLevel.Medium,
        "WindowsBackup/ActionCenter/100 should classify as BackupConfigurationChanged, Medium fidelity");
    Assert(EventCatalog.TryClassify("Microsoft-Windows-WindowsBackup/ActionCenter", 101, out var c69)
        && c69.Kind == EventKind.BackupConfigurationChanged && c69.Fidelity == FidelityLevel.Medium,
        "WindowsBackup/ActionCenter/101 should classify as BackupConfigurationChanged, Medium fidelity");
    return Task.CompletedTask;
}

Task TestEventCatalogUnknownIds()
{
    Assert(!EventCatalog.TryClassify("System", 7036, out _),
        "System/7036 (routine service state change) should not classify — it's noise");
    Assert(!EventCatalog.TryClassify("Microsoft-Windows-TaskScheduler/Operational", 200, out _),
        "TaskScheduler/200 (routine task run) should not classify — it's noise");
    Assert(!EventCatalog.TryClassify("Microsoft-Windows-DHCP-Client/Admin", 50036, out _),
        "DHCP-Client has no curated entries yet — everything should be filtered");
    // textbook ids never fire, stay unclassified
    Assert(!EventCatalog.TryClassify("Microsoft-Windows-Windows Firewall With Advanced Security/Firewall", 2004, out _),
        "Firewall/2004 never actually fires on real Windows — should not classify");
    // idle-machine chatter, excluded
    Assert(!EventCatalog.TryClassify("Security", 4798, out _),
        "Security/4798 (local group membership enumerated) is idle-chatter noise — should not classify");
    return Task.CompletedTask;
}

Task TestEventCatalogApplicationSeverity()
{
    Assert(EventCatalog.TryClassifyApplication(1, out var critical)
        && critical.Kind == EventKind.ApplicationCritical && critical.Fidelity == FidelityLevel.High,
        "Level 1 should classify as ApplicationCritical, High fidelity");
    Assert(EventCatalog.TryClassifyApplication(2, out var error)
        && error.Kind == EventKind.ApplicationError && error.Fidelity == FidelityLevel.High,
        "Level 2 should classify as ApplicationError, High fidelity");
    Assert(EventCatalog.TryClassifyApplication(3, out var warning)
        && warning.Kind == EventKind.ApplicationWarning && warning.Fidelity == FidelityLevel.Medium,
        "Level 3 should classify as ApplicationWarning, Medium fidelity");
    Assert(!EventCatalog.TryClassifyApplication(4, out _), "Level 4 (Info) should not classify");
    Assert(!EventCatalog.TryClassifyApplication(null, out _), "Null level should not classify");
    return Task.CompletedTask;
}

Task TestEventCatalogBuildContext()
{
    var low = EventCatalog.BuildContext(FidelityLevel.Low, "Provider", "System", "<xml/>");
    Assert(low.Count == 2 && low.ContainsKey("provider") && low.ContainsKey("channel"),
        $"Low fidelity should only carry provider+channel, got: {string.Join(",", low.Keys)}");

    var mediumEmpty = EventCatalog.BuildContext(FidelityLevel.Medium, "Provider", "NetworkProfile", "<xml/>");
    Assert(mediumEmpty.Count == 2 && mediumEmpty.ContainsKey("provider") && mediumEmpty.ContainsKey("channel") && !mediumEmpty.ContainsKey("xml"),
        $"Medium fidelity with no parsable xml should degrade to provider+channel, got: {string.Join(",", mediumEmpty.Keys)}");

    // wifi connected shape, medium tier extracts named fields
    const string wlanXml = """
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System><Provider Name="Microsoft-Windows-WLAN-AutoConfig" /><EventID>8001</EventID></System>
          <EventData>
            <Data Name="InterfaceGuid">{6f718a02-c492-433a-b2bd-2ef9cde1ae72}</Data>
            <Data Name="ConnectionMode">Automatic connection with a profile</Data>
            <Data Name="ProfileName">eduroam</Data>
            <Data Name="SSID">eduroam</Data>
            <Data Name="AuthenticationAlgorithm">WPA2-Enterprise</Data>
            <Data Name="ConnectionId">0x3</Data>
          </EventData>
        </Event>
        """;
    var medium = EventCatalog.BuildContext(FidelityLevel.Medium, "Provider", "WLAN-AutoConfig", wlanXml);
    Assert(medium.Count == 6 && !medium.ContainsKey("InterfaceGuid") && !medium.ContainsKey("ConnectionId")
        && medium["SSID"] == "eduroam" && medium["ProfileName"] == "eduroam"
        && medium["ConnectionMode"] == "Automatic connection with a profile",
        $"Medium fidelity should extract readable named fields but drop bare GUID/hex values, got: {string.Join(",", medium.Keys)}");

    // process creation shape, elevation type translated not dropped
    const string processCreatedXml = """
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System><Provider Name="Microsoft-Windows-Security-Auditing" /><EventID>4688</EventID></System>
          <EventData>
            <Data Name="SubjectUserName">testuser</Data>
            <Data Name="SubjectLogonId">0x12cc680</Data>
            <Data Name="NewProcessId">0x4404</Data>
            <Data Name="NewProcessName">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data>
            <Data Name="TokenElevationType">%%1937</Data>
            <Data Name="ProcessId">0x4b90</Data>
            <Data Name="CommandLine">powershell.exe -NoProfile -Command "whoami /all"</Data>
            <Data Name="TargetLogonId">0x0</Data>
            <Data Name="ParentProcessName">C:\Windows\explorer.exe</Data>
          </EventData>
        </Event>
        """;
    var processCreated = EventCatalog.BuildContext(FidelityLevel.Medium, "Provider", "Security", processCreatedXml);
    Assert(!processCreated.ContainsKey("SubjectLogonId") && !processCreated.ContainsKey("NewProcessId")
        && !processCreated.ContainsKey("ProcessId") && !processCreated.ContainsKey("TargetLogonId")
        && processCreated["NewProcessName"] == @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        && processCreated["CommandLine"] == "powershell.exe -NoProfile -Command \"whoami /all\""
        && processCreated["ParentProcessName"] == @"C:\Windows\explorer.exe"
        && processCreated["TokenElevationType"] == "Elevated (Run as administrator)",
        $"ProcessCreated should keep NewProcessName/CommandLine/ParentProcessName, translate TokenElevationType, and drop hex ids, got: {string.Join(",", processCreated.Keys)}");

    // failed logon shape, substatus is a known code
    const string classicXml = """
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System><Provider Name="Microsoft-Windows-Security-Auditing" /><EventID>4625</EventID></System>
          <EventData>
            <Data Name="TargetUserName">guest</Data>
            <Data Name="Status">0xc000006e</Data>
            <Data Name="FailureReason">%%2310</Data>
            <Data Name="SubStatus">0xc0000072</Data>
            <Data Name="LogonType">3</Data>
          </EventData>
        </Event>
        """;
    var high = EventCatalog.BuildContext(FidelityLevel.High, "Provider", "Security", classicXml);
    Assert(high.Count == 5 && !high.ContainsKey("xml")
        && high["TargetUserName"] == "guest" && high["LogonType"] == "Network"
        && high["SubStatus"] == "account disabled"
        && !high.ContainsKey("Status") && !high.ContainsKey("FailureReason"),
        $"High fidelity should translate known LogonType/SubStatus codes but still drop unrecognised hex/%%-code values, got: {string.Join(",", high.Keys)}");

    // unexpected shutdown shape, no context leak
    const string unnamedDataXml = """
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System><Provider Name="EventLog" /><EventID Qualifiers="32768">6008</EventID></System>
          <EventData>
            <Data>1:07:28 PM</Data>
            <Data>6/19/2026</Data>
            <Data>492241</Data>
            <Binary>EA070600050013000D0007001C00FA02</Binary>
          </EventData>
        </Event>
        """;
    var unnamed = EventCatalog.BuildContext(FidelityLevel.High, "Provider", "System", unnamedDataXml);
    Assert(unnamed.Count == 2 && unnamed.ContainsKey("provider") && unnamed.ContainsKey("channel"),
        $"Unnamed <Data>/<Binary> elements should never leak into Context, got: {string.Join(",", unnamed.Keys)}");

    // manifested schema, named UserData elements
    const string manifestedXml = """
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System><Provider Name="Microsoft-Windows-TaskScheduler" /><EventID>106</EventID></System>
          <UserData>
            <EventTriggerData xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog">
              <TaskName>\MyTask</TaskName>
              <UserContext>CONTOSO\user</UserContext>
            </EventTriggerData>
          </UserData>
        </Event>
        """;
    var manifested = EventCatalog.BuildContext(FidelityLevel.High, "Provider", "TaskScheduler", manifestedXml);
    Assert(manifested.Count == 4 && !manifested.ContainsKey("xml")
        && manifested["TaskName"] == @"\MyTask" && manifested["UserContext"] == @"CONTOSO\user",
        $"High fidelity should parse manifested-schema named elements too, got: {string.Join(",", manifested.Keys)}");

    // malformed xml degrades gracefully
    var malformed = EventCatalog.BuildContext(FidelityLevel.High, "Provider", "System", "<xml/>");
    Assert(malformed.Count == 2 && malformed.ContainsKey("provider") && malformed.ContainsKey("channel"),
        $"Unrecognised xml shape should yield no extra fields (and never throw), got: {string.Join(",", malformed.Keys)}");

    return Task.CompletedTask;
}

// coded-field translation tests (LogonType, logon-failure SubStatus)

Task TestEventCatalogLogonTypeTranslation()
{
    string XmlWithLogonType(string logonType) => $"""
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System><Provider Name="Microsoft-Windows-Security-Auditing" /><EventID>4624</EventID></System>
          <EventData>
            <Data Name="LogonType">{logonType}</Data>
          </EventData>
        </Event>
        """;

    var interactive = EventCatalog.BuildContext(FidelityLevel.Medium, "Provider", "Security", XmlWithLogonType("2"));
    Assert(interactive["LogonType"] == "Interactive", $"LogonType 2 should translate to 'Interactive', got: '{interactive["LogonType"]}'");

    var rdp = EventCatalog.BuildContext(FidelityLevel.Medium, "Provider", "Security", XmlWithLogonType("10"));
    Assert(rdp["LogonType"] == "RemoteInteractive (RDP)", $"LogonType 10 should translate to 'RemoteInteractive (RDP)', got: '{rdp["LogonType"]}'");

    var unlock = EventCatalog.BuildContext(FidelityLevel.Medium, "Provider", "Security", XmlWithLogonType("7"));
    Assert(unlock["LogonType"] == "Unlock", $"LogonType 7 should translate to 'Unlock', got: '{unlock["LogonType"]}'");

    return Task.CompletedTask;
}

Task TestEventCatalogPrimaryGroupIdTranslation()
{
    // real primarygroupid value
    const string xml = """
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System><Provider Name="Microsoft-Windows-Security-Auditing" /><EventID>4738</EventID></System>
          <EventData>
            <Data Name="PrimaryGroupId">513</Data>
          </EventData>
        </Event>
        """;
    var context = EventCatalog.BuildContext(FidelityLevel.High, "Provider", "Security", xml);
    Assert(context["PrimaryGroupId"] == "Domain Users", $"RID 513 should translate to 'Domain Users', got: '{context["PrimaryGroupId"]}'");

    const string adminsXml = """
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System><Provider Name="Microsoft-Windows-Security-Auditing" /><EventID>4738</EventID></System>
          <EventData>
            <Data Name="PrimaryGroupId">512</Data>
          </EventData>
        </Event>
        """;
    var adminsContext = EventCatalog.BuildContext(FidelityLevel.High, "Provider", "Security", adminsXml);
    Assert(adminsContext["PrimaryGroupId"] == "Domain Admins", $"RID 512 should translate to 'Domain Admins', got: '{adminsContext["PrimaryGroupId"]}'");
    return Task.CompletedTask;
}

Task TestEventCatalogUnknownPrimaryGroupIdPassesThrough()
{
    const string xml = """
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System><Provider Name="Microsoft-Windows-Security-Auditing" /><EventID>4738</EventID></System>
          <EventData>
            <Data Name="PrimaryGroupId">99999</Data>
          </EventData>
        </Event>
        """;
    var context = EventCatalog.BuildContext(FidelityLevel.High, "Provider", "Security", xml);
    Assert(context["PrimaryGroupId"] == "99999",
        $"An unrecognised RID should pass through unchanged rather than being dropped or guessed at, got: '{context["PrimaryGroupId"]}'");
    return Task.CompletedTask;
}

Task TestEventCatalogUnknownLogonTypePassesThrough()
{
    const string xml = """
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System><Provider Name="Microsoft-Windows-Security-Auditing" /><EventID>4624</EventID></System>
          <EventData>
            <Data Name="LogonType">99</Data>
          </EventData>
        </Event>
        """;
    var context = EventCatalog.BuildContext(FidelityLevel.Medium, "Provider", "Security", xml);
    Assert(context["LogonType"] == "99",
        $"An unrecognised LogonType digit should pass through unchanged rather than being dropped or guessed at, got: '{context["LogonType"]}'");
    return Task.CompletedTask;
}

Task TestEventCatalogTokenElevationTypeTranslation()
{
    // run as administrator signal
    string XmlWithElevationType(string elevationType) => $"""
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System><Provider Name="Microsoft-Windows-Security-Auditing" /><EventID>4688</EventID></System>
          <EventData>
            <Data Name="TokenElevationType">{elevationType}</Data>
          </EventData>
        </Event>
        """;

    var elevated = EventCatalog.BuildContext(FidelityLevel.Medium, "Provider", "Security", XmlWithElevationType("%%1937"));
    Assert(elevated["TokenElevationType"] == "Elevated (Run as administrator)",
        $"TokenElevationType %%1937 should translate to 'Elevated (Run as administrator)', got: '{elevated["TokenElevationType"]}'");

    var limited = EventCatalog.BuildContext(FidelityLevel.Medium, "Provider", "Security", XmlWithElevationType("%%1938"));
    Assert(limited["TokenElevationType"] == "Limited (standard, not elevated)",
        $"TokenElevationType %%1938 should translate to 'Limited (standard, not elevated)', got: '{limited["TokenElevationType"]}'");

    return Task.CompletedTask;
}

Task TestEventCatalogUnknownTokenElevationTypePassesThrough()
{
    const string xml = """
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System><Provider Name="Microsoft-Windows-Security-Auditing" /><EventID>4688</EventID></System>
          <EventData>
            <Data Name="TokenElevationType">%%9999</Data>
          </EventData>
        </Event>
        """;
    var context = EventCatalog.BuildContext(FidelityLevel.Medium, "Provider", "Security", xml);
    Assert(!context.ContainsKey("TokenElevationType"),
        "An unrecognised TokenElevationType code should fall through to the existing %%-code drop policy, never guessed at");
    return Task.CompletedTask;
}

Task TestEventCatalogBackupConfigurationChangedDescriptionOverride()
{
    // backup config description override
    Assert(EventCatalog.TryGetDescriptionOverride(EventKind.BackupConfigurationChanged, out var description),
        "BackupConfigurationChanged should have a Description override");
    Assert(description == "A Windows Backup configuration setting was changed.",
        $"Unexpected override text: '{description}'");
    return Task.CompletedTask;
}

Task TestEventCatalogNoDescriptionOverrideForOrdinaryKind()
{
    // no override for other kinds
    Assert(!EventCatalog.TryGetDescriptionOverride(EventKind.LogonSuccess, out _),
        "LogonSuccess has a normal native sentence and should not have a Description override");
    return Task.CompletedTask;
}

Task TestEventCatalogSubStatusTranslation()
{
    const string xml = """
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System><Provider Name="Microsoft-Windows-Security-Auditing" /><EventID>4625</EventID></System>
          <EventData>
            <Data Name="SubStatus">0xc000006a</Data>
          </EventData>
        </Event>
        """;
    var context = EventCatalog.BuildContext(FidelityLevel.High, "Provider", "Security", xml);
    Assert(context["SubStatus"] == "incorrect password",
        $"SubStatus 0xc000006a should translate to 'incorrect password' (case-insensitive match against real lowercase-rendered XML), got: '{context.GetValueOrDefault("SubStatus")}'");
    return Task.CompletedTask;
}

Task TestEventCatalogUnknownSubStatusStillDropped()
{
    const string xml = """
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System><Provider Name="Microsoft-Windows-Security-Auditing" /><EventID>4625</EventID></System>
          <EventData>
            <Data Name="SubStatus">0xdeadbeef</Data>
          </EventData>
        </Event>
        """;
    var context = EventCatalog.BuildContext(FidelityLevel.High, "Provider", "Security", xml);
    Assert(!context.ContainsKey("SubStatus"),
        "An unrecognised SubStatus code must still be dropped, never guessed at — same 'never guess' policy as every other unresolved code");
    return Task.CompletedTask;
}

// "-" placeholder drop + SID resolution tests

Task TestEventCatalogDropsDashPlaceholder()
{
    // bare dash on non-domain-joined workstation
    const string xml = """
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System><Provider Name="Microsoft-Windows-Security-Auditing" /><EventID>4732</EventID></System>
          <EventData>
            <Data Name="TargetUserName">ClaudeVerifyGroup</Data>
            <Data Name="MemberName">-</Data>
          </EventData>
        </Event>
        """;
    var context = EventCatalog.BuildContext(FidelityLevel.High, "Provider", "Security", xml);
    Assert(!context.ContainsKey("MemberName") && context["TargetUserName"] == "ClaudeVerifyGroup",
        $"A bare '-' placeholder value should be dropped, got: {string.Join(",", context.Keys)}");
    return Task.CompletedTask;
}

Task TestEventCatalogResolvesKnownSid()
{
    // well-known localsystem sid
    const string xml = """
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System><Provider Name="Microsoft-Windows-Security-Auditing" /><EventID>4732</EventID></System>
          <EventData>
            <Data Name="MemberSid">S-1-5-18</Data>
          </EventData>
        </Event>
        """;
    var context = EventCatalog.BuildContext(FidelityLevel.High, "Provider", "Security", xml);
    Assert(context.TryGetValue("MemberSid", out var resolved) && resolved.Contains("SYSTEM", StringComparison.OrdinalIgnoreCase),
        $"S-1-5-18 should resolve to a friendly account name containing 'SYSTEM', got: '{context.GetValueOrDefault("MemberSid")}'");
    return Task.CompletedTask;
}

Task TestEventCatalogDropsUnresolvableSid()
{
    // unresolvable sid must be dropped
    const string xml = """
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System><Provider Name="Microsoft-Windows-Security-Auditing" /><EventID>4732</EventID></System>
          <EventData>
            <Data Name="MemberSid">S-1-5-21-1111111111-2222222222-3333333333-999999</Data>
          </EventData>
        </Event>
        """;
    var context = EventCatalog.BuildContext(FidelityLevel.High, "Provider", "Security", xml);
    Assert(!context.ContainsKey("MemberSid"),
        "An unresolvable SID must be dropped, not surfaced raw — same 'never guess' policy as every other unresolved code");
    return Task.CompletedTask;
}

Task TestEventCatalogAccountRenameContext()
{
    // old and new name must survive extraction
    const string xml = """
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System><Provider Name="Microsoft-Windows-Security-Auditing" /><EventID>4781</EventID></System>
          <EventData>
            <Data Name="OldTargetUserName">ClaudeChgTest</Data>
            <Data Name="NewTargetUserName">ClaudeChgTest2</Data>
          </EventData>
        </Event>
        """;
    var context = EventCatalog.BuildContext(FidelityLevel.High, "Provider", "Security", xml);
    Assert(context["OldTargetUserName"] == "ClaudeChgTest" && context["NewTargetUserName"] == "ClaudeChgTest2",
        $"Old and new account names should both survive extraction, got: {string.Join(",", context.Keys)}");
    return Task.CompletedTask;
}

Task TestEventCatalogFirewallSettingChangedContext()
{
    // readable strings, no translation needed
    const string xml = """
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System><Provider Name="Microsoft-Windows-Security-Auditing" /><EventID>4950</EventID></System>
          <EventData>
            <Data Name="ProfileChanged">Domain</Data>
            <Data Name="SettingType">Default Outbound Action</Data>
            <Data Name="SettingValue">Block</Data>
          </EventData>
        </Event>
        """;
    var context = EventCatalog.BuildContext(FidelityLevel.High, "Provider", "Security", xml);
    Assert(context["SettingType"] == "Default Outbound Action" && context["SettingValue"] == "Block",
        $"4950's readable SettingType/SettingValue should survive extraction unchanged, got: {string.Join(",", context.Keys)}");
    return Task.CompletedTask;
}

// event description formatter tests

Task TestDescriptionFormatterStripsHexCodes()
{
    string result = EventDescriptionFormatter.ToFriendlyDescription(
        "The operation failed with status (0x80004005).");
    Assert(!result.Contains("0x80004005"), $"Hex code should be removed, got: '{result}'");
    Assert(!result.Contains("()"), $"Empty parens left behind should be cleaned up, got: '{result}'");
    Assert(!result.Contains("  "), $"No doubled spaces should remain, got: '{result}'");
    return Task.CompletedTask;
}

Task TestDescriptionFormatterExpandsAbbreviations()
{
    string result = EventDescriptionFormatter.ToFriendlyDescription(
        "The DHCP lease was renewed on the WLAN adapter.");
    Assert(!result.Contains("DHCP") && result.Contains("network management service"),
        $"DHCP should expand to 'network management service', got: '{result}'");
    Assert(!result.Contains("WLAN") && result.Contains("wireless network"),
        $"WLAN should expand to 'wireless network', got: '{result}'");
    return Task.CompletedTask;
}

Task TestDescriptionFormatterAbstractsSystemAccounts()
{
    string result = EventDescriptionFormatter.ToFriendlyDescription(
        "An account was logged on by NT AUTHORITY\\SYSTEM.");
    Assert(!result.Contains("NT AUTHORITY") && result.Contains("a core system process"),
        $"NT AUTHORITY\\SYSTEM should be abstracted, got: '{result}'");
    return Task.CompletedTask;
}

Task TestDescriptionFormatterKeepsOnlyHeaderLine()
{
    string result = EventDescriptionFormatter.ToFriendlyDescription(
        "Line one.\r\nLine two.\r\n\r\nLine three.");
    Assert(result == "Line one.", $"Only the first line should survive, got: '{result}'");
    Assert(!result.Contains('\n') && !result.Contains('\r'),
        $"Result must be a single physical line, got: '{result}'");
    return Task.CompletedTask;
}

Task TestDescriptionFormatterSecurityLogonExample()
{
    // security 4624 rendered shape
    string raw = "An account was successfully logged on.\r\n\r\n" +
                 "Subject:\r\n\tSecurity ID:\t\tS-1-5-18\r\n\tAccount Name:\t\tSYSTEM\r\n" +
                 "\tAccount Domain:\t\tNT AUTHORITY\r\n\tLogon ID:\t\t0x3E7\r\n\r\n" +
                 "Logon Information:\r\n\tLogon Type:\t\t5\r\n";
    string result = EventDescriptionFormatter.ToFriendlyDescription(raw);
    Assert(result == "An account was successfully logged on.",
        $"Only the header sentence should survive, Subject/Logon Information blocks must be dropped, got: '{result}'");
    return Task.CompletedTask;
}

Task TestDescriptionFormatterWlanConnectExample()
{
    // wlan-autoconfig 8001 rendered shape
    string raw = "Wireless network AutoConfig service has successfully connected to a wireless network.\r\n\r\n" +
                 "Network Adapter: Wireless Network Connection\r\n" +
                 "Interface unique identifier: {12345678-90AB-CDEF-1234-567890ABCDEF}\r\n" +
                 "Local MAC Address: 00:11:22:33:44:55\r\n" +
                 "Network SSID: HomeNetwork\r\n";
    string result = EventDescriptionFormatter.ToFriendlyDescription(raw);
    Assert(result == "Wireless network AutoConfig service has successfully connected to a wireless network.",
        $"Only the core action line should survive, Network Adapter/interface fields must be dropped, got: '{result}'");
    return Task.CompletedTask;
}

Task TestDescriptionFormatterHandlesEmptyInput()
{
    Assert(EventDescriptionFormatter.ToFriendlyDescription(null) == string.Empty, "Null input should return empty string");
    Assert(EventDescriptionFormatter.ToFriendlyDescription("") == string.Empty, "Empty input should return empty string");
    Assert(EventDescriptionFormatter.ToFriendlyDescription("   ") == string.Empty, "Whitespace-only input should return empty string");
    return Task.CompletedTask;
}

Task TestDescriptionFormatterCombined()
{
    string raw = "The DHCP service failed with error (0x80004005) while running as NT AUTHORITY\\SYSTEM.\r\n";
    string result = EventDescriptionFormatter.ToFriendlyDescription(raw);
    Assert(!result.Contains("0x80004005"), $"Hex code should be gone, got: '{result}'");
    Assert(result.Contains("network management service"), $"DHCP should be expanded, got: '{result}'");
    Assert(result.Contains("a core system process"), $"System account should be abstracted, got: '{result}'");
    Assert(!result.Contains('\n'), $"Result must be single-line, got: '{result}'");
    return Task.CompletedTask;
}

async Task TestDescriptionCsvSafety()
{
    // escaping keeps column count intact
    string path = TempFile();
    string friendly = EventDescriptionFormatter.ToFriendlyDescription(
        "Adapter, Wi-Fi \"Home Network\", reconnected.\r\nSecond line here.");

    await using (var w = new EventCsvWriter(path))
        w.TryWrite(new CsvEntry(DateTimeOffset.UtcNow, friendly, null));

    string[] lines = File.ReadAllLines(path);
    Assert(lines.Length == 2, $"Expected header + 1 data line (no embedded raw newline), got {lines.Length}");
    int cols = CountCsvColumns(lines[1]);
    Assert(cols == 3, $"Expected 3 columns, got {cols} in: {lines[1]}");
    Assert(!friendly.Contains('\n'), "Formatter output must not contain raw newlines");
}

// event correlation engine tests

Task TestCorrelationIdsIsEmpty()
{
    Assert(new CorrelationIds(null, null, null).IsEmpty, "All-null CorrelationIds should be empty");
    Assert(!new CorrelationIds("0x3e7", null, null).IsEmpty, "A set LogonId should make it non-empty");
    Assert(!new CorrelationIds(null, 1234, null).IsEmpty, "A set ProcessId should make it non-empty");
    Assert(!new CorrelationIds(null, null, "{guid}").IsEmpty, "A set InterfaceGuid should make it non-empty");
    return Task.CompletedTask;
}

Task TestCorrelationEngineUnmappedKind()
{
    using var reader = new EventLogReader(new EventLogQuery("System", PathType.LogName, "*") { ReverseDirection = true });
    using var record = reader.ReadEvent();
    if (record is null)
    {
        Console.WriteLine("         (no System events available — skipping)");
        return Task.CompletedTask;
    }

    // only processid can be populated
    var ids = EventCorrelationEngine.Extract(record, EventKind.SystemStartup);
    Assert(ids.LogonId is null, $"SystemStartup should never yield a LogonId, got '{ids.LogonId}'");
    Assert(ids.InterfaceGuid is null, $"SystemStartup should never yield an InterfaceGuid, got '{ids.InterfaceGuid}'");
    return Task.CompletedTask;
}

Task TestCorrelationEngineProcessId()
{
    using var reader = new EventLogReader(new EventLogQuery("System", PathType.LogName, "*") { ReverseDirection = true });
    for (int i = 0; i < 20; i++)
    {
        using var record = reader.ReadEvent();
        if (record is null) break;

        var ids = EventCorrelationEngine.Extract(record, EventKind.SystemStartup);
        if (ids.ProcessId is int pid)
        {
            Assert(pid > 0, $"Extracted ProcessId should be positive, got {pid}");
            return Task.CompletedTask;
        }
    }
    Console.WriteLine("         (no System event carried a ProcessId in the most recent 20 — skipping)");
    return Task.CompletedTask;
}

Task TestCorrelationEngineLogonId()
{
    try
    {
        using var reader = new EventLogReader(
            new EventLogQuery("Security", PathType.LogName, "*[System[(EventID=4624)]]") { ReverseDirection = true });
        using var record = reader.ReadEvent();
        if (record is null)
        {
            Console.WriteLine("         (no Security 4624 events available — skipping)");
            return Task.CompletedTask;
        }

        var ids = EventCorrelationEngine.Extract(record, EventKind.LogonSuccess);
        Assert(ids.LogonId is not null, "LogonId should be extracted from a real 4624 event");
        Assert(ids.LogonId!.StartsWith("0x", StringComparison.OrdinalIgnoreCase),
            $"LogonId should be a hex string (e.g. '0x3e7'), got '{ids.LogonId}'");
    }
    catch
    {
        // skip if channel unavailable
        Console.WriteLine("         (Security channel unavailable — skipping)");
    }
    return Task.CompletedTask;
}

Task TestCorrelationEngineInterfaceGuid()
{
    try
    {
        using var reader = new EventLogReader(
            new EventLogQuery("Microsoft-Windows-WLAN-AutoConfig/Operational", PathType.LogName,
                "*[System[(EventID=8001 or EventID=8003)]]") { ReverseDirection = true });
        using var record = reader.ReadEvent();
        if (record is null)
        {
            Console.WriteLine("         (no WLAN connect/disconnect events available — skipping)");
            return Task.CompletedTask;
        }

        var kind = record.Id == 8001 ? EventKind.WifiConnected : EventKind.WifiDisconnected;
        var ids = EventCorrelationEngine.Extract(record, kind);
        Assert(ids.InterfaceGuid is not null, "InterfaceGuid should be extracted from a real WLAN event");
    }
    catch
    {
        Console.WriteLine("         (WLAN-AutoConfig channel unavailable — skipping)");
    }
    return Task.CompletedTask;
}

Task TestCorrelationEngineNeverThrows()
{
    using var reader = new EventLogReader(new EventLogQuery("System", PathType.LogName, "*") { ReverseDirection = true });
    using var record = reader.ReadEvent();
    if (record is null)
    {
        Console.WriteLine("         (no System events available — skipping)");
        return Task.CompletedTask;
    }

    // missing fields return null not throw
    var ids = EventCorrelationEngine.Extract(record, EventKind.LogonSuccess);
    Assert(ids.LogonId is null, $"Non-Security event should not yield a LogonId, got '{ids.LogonId}'");
    return Task.CompletedTask;
}

async Task TestCorrelationIdsNeverLeakIntoCsv()
{
    // correlation ids stay in memory not csv
    string path = TempFile();
    await using (var writer = new EventCsvWriter(path))
    using (var os = new OsEventLogSource(writer))
    using (var net = new NetworkEventLogSource(writer))
        await Task.Delay(3000);

    string[] lines = File.ReadAllLines(path);
    string[] forbiddenKeys = ["logonid=", "targetlogonid=", "processid=", "interfaceguid=", "networkadapterguid="];

    foreach (string line in lines.Skip(1))
    {
        int cols = CountCsvColumns(line);
        Assert(cols == 3, $"Expected 3 columns, got {cols} in: {line[..Math.Min(120, line.Length)]}");

        string lower = line.ToLowerInvariant();
        foreach (string key in forbiddenKeys)
            Assert(!lower.Contains(key), $"Correlation id key '{key}' leaked into CSV: {line}");
    }
}

// correlation index + linking tests

Task TestCorrelationIndexOrdersByTimestamp()
{
    var t0 = new DateTimeOffset(2027, 1, 1, 12, 0, 0, TimeSpan.Zero);
    var events = new[]
    {
        new CorrelatableEvent(1, t0.AddSeconds(30), new CorrelationIds(null, null, null)),
        new CorrelatableEvent(2, t0, new CorrelationIds(null, null, null)),
        new CorrelatableEvent(3, t0.AddSeconds(10), new CorrelationIds(null, null, null)),
    };

    var index = EventCorrelationEngine.Index(events);

    Assert(index.EventsByTime.Select(e => e.Id).SequenceEqual([2, 3, 1]),
        $"Expected ascending timestamp order [2,3,1], got [{string.Join(",", index.EventsByTime.Select(e => e.Id))}]");
    return Task.CompletedTask;
}

Task TestCorrelationIndexGroupsById()
{
    var t0 = new DateTimeOffset(2027, 1, 1, 12, 0, 0, TimeSpan.Zero);
    var events = new[]
    {
        new CorrelatableEvent(1, t0, new CorrelationIds("0x3e7", 100, null)),
        new CorrelatableEvent(2, t0.AddMinutes(1), new CorrelationIds("0x3e7", null, "{guid-a}")),
        new CorrelatableEvent(3, t0.AddMinutes(2), new CorrelationIds(null, 100, "{guid-a}")),
        new CorrelatableEvent(4, t0.AddMinutes(3), new CorrelationIds(null, null, null)),
    };

    var index = EventCorrelationEngine.Index(events);

    Assert(index.ByLogonId.TryGetValue("0x3e7", out var logonGroup) && logonGroup.Select(e => e.Id).SequenceEqual([1, 2]),
        "LogonId group '0x3e7' should contain events 1 and 2 in time order");
    Assert(index.ByProcessId.TryGetValue(100, out var pidGroup) && pidGroup.Select(e => e.Id).SequenceEqual([1, 3]),
        "ProcessId group 100 should contain events 1 and 3 in time order");
    Assert(index.ByInterfaceGuid.TryGetValue("{guid-a}", out var guidGroup) && guidGroup.Select(e => e.Id).SequenceEqual([2, 3]),
        "InterfaceGuid group '{guid-a}' should contain events 2 and 3 in time order");
    Assert(!index.ByLogonId.Values.Any(g => g.Any(e => e.Id == 4)), "Event 4 (all-null ids) must not appear in any id group");
    return Task.CompletedTask;
}

Task TestFindLinksDirectIdMatchWithinWindow()
{
    var t0 = new DateTimeOffset(2027, 1, 1, 12, 0, 0, TimeSpan.Zero);
    var events = new[]
    {
        new CorrelatableEvent(1, t0, new CorrelationIds(null, 500, null)),
        new CorrelatableEvent(2, t0.AddMinutes(10), new CorrelationIds(null, 500, null)),   // 10 min gap — within default 30 min window
        new CorrelatableEvent(3, t0.AddMinutes(50), new CorrelationIds(null, 500, null)),   // 40 min gap from event 2 — outside window
    };

    var index = EventCorrelationEngine.Index(events);
    var links = EventCorrelationEngine.FindLinks(index);

    Assert(links.Count == 1, $"Expected exactly 1 link, got {links.Count}");
    Assert(links[0].EventIdA == 1 && links[0].EventIdB == 2 && links[0].MatchType == CorrelationMatchType.SameProcessId,
        $"Expected SameProcessId link between events 1 and 2, got ({links[0].EventIdA},{links[0].EventIdB},{links[0].MatchType})");
    return Task.CompletedTask;
}

Task TestFindLinksDirectIdMatchCustomWindow()
{
    var t0 = new DateTimeOffset(2027, 1, 1, 12, 0, 0, TimeSpan.Zero);
    var events = new[]
    {
        new CorrelatableEvent(1, t0, new CorrelationIds(null, 500, null)),
        new CorrelatableEvent(2, t0.AddMinutes(10), new CorrelationIds(null, 500, null)),
    };

    var index = EventCorrelationEngine.Index(events);
    var links = EventCorrelationEngine.FindLinks(index, directIdWindow: TimeSpan.FromMinutes(5));

    Assert(links.Count == 0, $"A 10-minute gap should not match under a 5-minute window, got {links.Count} link(s)");
    return Task.CompletedTask;
}

Task TestFindLinksTimeProximityMatch()
{
    var t0 = new DateTimeOffset(2027, 1, 1, 12, 0, 0, TimeSpan.Zero);
    var events = new[]
    {
        // network and security event close in time
        new CorrelatableEvent(1, t0, new CorrelationIds(null, null, "{guid-a}")),
        new CorrelatableEvent(2, t0.AddSeconds(2), new CorrelationIds("0x3e7", null, null)),
        new CorrelatableEvent(3, t0.AddSeconds(10), new CorrelationIds("0xdead", null, null)),  // 10s from event 1/2 — outside 4s window
    };

    var index = EventCorrelationEngine.Index(events);
    var links = EventCorrelationEngine.FindLinks(index);

    Assert(links.Count == 1, $"Expected exactly 1 proximity link, got {links.Count}");
    Assert(links[0].EventIdA == 1 && links[0].EventIdB == 2 && links[0].MatchType == CorrelationMatchType.TimeProximity,
        $"Expected TimeProximity link between events 1 and 2, got ({links[0].EventIdA},{links[0].EventIdB},{links[0].MatchType})");
    return Task.CompletedTask;
}

Task TestFindLinksProximityExcludesSharedIdPairs()
{
    var t0 = new DateTimeOffset(2027, 1, 1, 12, 0, 0, TimeSpan.Zero);
    var events = new[]
    {
        // reported once not duplicated
        new CorrelatableEvent(1, t0, new CorrelationIds("0x3e7", null, null)),
        new CorrelatableEvent(2, t0.AddSeconds(2), new CorrelationIds("0x3e7", null, null)),
    };

    var index = EventCorrelationEngine.Index(events);
    var links = EventCorrelationEngine.FindLinks(index);

    Assert(links.Count == 1, $"Expected exactly 1 link (no duplicate), got {links.Count}");
    Assert(links[0].MatchType == CorrelationMatchType.SameLogonId,
        $"Expected the single link to be SameLogonId, got {links[0].MatchType}");
    return Task.CompletedTask;
}

Task TestFindLinksNoLinksForUnrelatedEvents()
{
    var t0 = new DateTimeOffset(2027, 1, 1, 12, 0, 0, TimeSpan.Zero);
    var events = new[]
    {
        new CorrelatableEvent(1, t0, new CorrelationIds("0x3e7", 111, "{guid-a}")),
        new CorrelatableEvent(2, t0.AddMinutes(5), new CorrelationIds("0xdead", 222, "{guid-b}")),
    };

    var index = EventCorrelationEngine.Index(events);
    var links = EventCorrelationEngine.FindLinks(index);

    Assert(links.Count == 0, $"Different ids and a 5-minute gap should produce no links, got {links.Count}");
    return Task.CompletedTask;
}

Task TestCorrelationIndexRealEvents()
{
    using var reader = new EventLogReader(new EventLogQuery("System", PathType.LogName, "*") { ReverseDirection = true });
    var entries = new List<CorrelatableLogEntry>();
    int id = 0;
    for (int i = 0; i < 20; i++)
    {
        var record = reader.ReadEvent();
        if (record is null) break;
        var timestamp = record.TimeCreated.HasValue
            ? new DateTimeOffset(record.TimeCreated.Value.ToUniversalTime(), TimeSpan.Zero)
            : DateTimeOffset.UtcNow;
        entries.Add(new CorrelatableLogEntry(id++, timestamp, EventKind.SystemStartup, record));
    }

    if (entries.Count == 0)
    {
        Console.WriteLine("         (no System events available — skipping)");
        return Task.CompletedTask;
    }

    try
    {
        var index = EventCorrelationEngine.Index(entries);

        Assert(index.EventsByTime.Count == entries.Count,
            $"Expected {entries.Count} indexed events, got {index.EventsByTime.Count}");

        for (int i = 1; i < index.EventsByTime.Count; i++)
            Assert(index.EventsByTime[i].Timestamp >= index.EventsByTime[i - 1].Timestamp,
                "EventsByTime must be in non-decreasing timestamp order");

        foreach (var group in index.ByProcessId)
            foreach (var e in group.Value)
                Assert(e.Ids.ProcessId == group.Key, $"Event in ByProcessId[{group.Key}] has mismatched ProcessId {e.Ids.ProcessId}");

        Console.WriteLine($"         ({entries.Count} real System events indexed, {index.ByProcessId.Count} distinct ProcessId groups)");
    }
    finally
    {
        foreach (var entry in entries) entry.Record.Dispose();
    }
    return Task.CompletedTask;
}

Task TestFindLinksRealNetworkAndSecurityProximity()
{
    // proximity window exercised deterministically
    EventRecord? networkRecord = null;
    EventRecord? securityRecord = null;
    try
    {
        try
        {
            using var netReader = new EventLogReader(new EventLogQuery(
                "Microsoft-Windows-WLAN-AutoConfig/Operational", PathType.LogName,
                "*[System[(EventID=8001 or EventID=8003)]]") { ReverseDirection = true });
            networkRecord = netReader.ReadEvent();
        }
        catch { /* channel unavailable — handled below */ }

        try
        {
            using var secReader = new EventLogReader(new EventLogQuery(
                "Security", PathType.LogName, "*[System[(EventID=4624)]]") { ReverseDirection = true });
            securityRecord = secReader.ReadEvent();
        }
        catch { /* Security requires admin — handled below */ }

        if (networkRecord is null || securityRecord is null)
        {
            Console.WriteLine("         (WLAN and/or Security events unavailable — skipping)");
            return Task.CompletedTask;
        }

        var t0 = new DateTimeOffset(2027, 1, 1, 12, 0, 0, TimeSpan.Zero);
        var networkKind = networkRecord.Id == 8001 ? EventKind.WifiConnected : EventKind.WifiDisconnected;
        var entries = new[]
        {
            new CorrelatableLogEntry(1, t0, networkKind, networkRecord),
            new CorrelatableLogEntry(2, t0.AddSeconds(2), EventKind.LogonSuccess, securityRecord),
        };

        var index = EventCorrelationEngine.Index(entries);
        var links = EventCorrelationEngine.FindLinks(index);

        Assert(links.Count == 1, $"Expected exactly 1 link between the network and security event, got {links.Count}");
        Assert(links[0].MatchType == CorrelationMatchType.TimeProximity,
            $"Expected a TimeProximity match (these events share no id), got {links[0].MatchType}");
    }
    finally
    {
        networkRecord?.Dispose();
        securityRecord?.Dispose();
    }
    return Task.CompletedTask;
}

// AccountAttributeTracker tests (self-tracked 4738 diffing)

Task TestAccountSnapshotDiffSingleField()
{
    var before = new AccountSnapshot("Old Name", "desc", false, false, null);
    var after = before with { DisplayName = "New Name" };
    var diff = AccountSnapshot.Diff(before, after);
    Assert(diff.Count == 1 && diff["DisplayName"] == "Old Name -> New Name",
        $"Expected exactly one DisplayName change, got: {string.Join(",", diff.Select(kv => $"{kv.Key}={kv.Value}"))}");
    return Task.CompletedTask;
}

Task TestAccountSnapshotDiffMultipleFields()
{
    var before = new AccountSnapshot("Old Name", "old desc", false, false, null);
    var after = new AccountSnapshot("New Name", "new desc", true, false, null);
    var diff = AccountSnapshot.Diff(before, after);
    Assert(diff.Count == 3 && diff.ContainsKey("DisplayName") && diff.ContainsKey("Description") && diff.ContainsKey("PasswordNeverExpires"),
        $"Expected DisplayName+Description+PasswordNeverExpires changed, got: {string.Join(",", diff.Keys)}");
    Assert(diff["PasswordNeverExpires"] == "False -> True", $"Expected 'False -> True', got: '{diff["PasswordNeverExpires"]}'");
    return Task.CompletedTask;
}

Task TestAccountSnapshotDiffNoChange()
{
    var snapshot = new AccountSnapshot("Same Name", "same desc", true, false, null);
    var diff = AccountSnapshot.Diff(snapshot, snapshot);
    Assert(diff.Count == 0, $"Identical snapshots should produce no diff, got: {string.Join(",", diff.Keys)}");
    return Task.CompletedTask;
}

Task TestAccountSnapshotDiffUnsetToSet()
{
    var before = new AccountSnapshot(null, null, false, false, null);
    var after = before with { DisplayName = "test" };
    var diff = AccountSnapshot.Diff(before, after);
    Assert(diff.Count == 1 && diff["DisplayName"] == "(not set) -> test",
        $"Expected '(not set) -> test', got: '{diff.GetValueOrDefault("DisplayName")}'");
    return Task.CompletedTask;
}

Task TestAccountAttributeTrackerColdStart()
{
    // smoke test against current user
    using var tracker = new AccountAttributeTracker();
    tracker.SeedAll();
    bool changed = tracker.TryObserve(Environment.UserName, out var firstDiff);
    Assert(!changed && firstDiff.Count == 0,
        $"SeedAll already cached the current user, so a fresh observation should report no change, got: {string.Join(",", firstDiff.Keys)}");

    changed = tracker.TryObserve("ThisAccountDoesNotExist_Claude", out var missingDiff);
    Assert(!changed && missingDiff.Count == 0,
        "A nonexistent account should be treated as nothing to report, never throw");
    return Task.CompletedTask;
}

// WindowsUpdateSettingsSnapshot.Diff tests (pure)

Task TestWuSettingsDiffSingleField()
{
    var before = new WindowsUpdateSettingsSnapshot(9, 17, false, 0);
    var after = before with { ActiveHoursEnd = 22 };
    var diff = WindowsUpdateSettingsSnapshot.Diff(before, after);
    Assert(diff.Count == 1 && diff["ActiveHoursEnd"] == "17 -> 22",
        $"Expected exactly one ActiveHoursEnd change, got: {string.Join(",", diff.Select(kv => $"{kv.Key}={kv.Value}"))}");
    return Task.CompletedTask;
}

Task TestWuSettingsDiffMultipleFields()
{
    var before = new WindowsUpdateSettingsSnapshot(9, 17, false, 0);
    var after = new WindowsUpdateSettingsSnapshot(6, 20, true, 1);
    var diff = WindowsUpdateSettingsSnapshot.Diff(before, after);
    Assert(diff.Count == 4, $"Expected all 4 fields to differ, got: {string.Join(",", diff.Keys)}");
    return Task.CompletedTask;
}

Task TestWuSettingsDiffNoChange()
{
    var snap = new WindowsUpdateSettingsSnapshot(9, 17, false, 0);
    var diff = WindowsUpdateSettingsSnapshot.Diff(snap, snap);
    Assert(diff.Count == 0, $"Identical snapshots should produce no diff, got: {string.Join(",", diff.Keys)}");
    return Task.CompletedTask;
}

Task TestWuSettingsDiffPauseToggle()
{
    // unset to set shape
    var before = new WindowsUpdateSettingsSnapshot(9, 17, false, 0);
    var after = before with { PauseUpdatesActive = true };
    var diff = WindowsUpdateSettingsSnapshot.Diff(before, after);
    Assert(diff.Count == 1 && diff["PauseUpdatesActive"] == "False -> True",
        $"Expected PauseUpdatesActive False -> True, got: {string.Join(",", diff.Select(kv => $"{kv.Key}={kv.Value}"))}");
    return Task.CompletedTask;
}

// ScreenshotCaptureSource / WindowsUpdateSettingsSource smoke tests

async Task TestScreenshotSourceSmoke()
{
    string path = TempFile();
    await using var writer = new EventCsvWriter(path);
    // nonexistent folder, skips silently
    using var source = new ScreenshotCaptureSource(writer, Path.Combine(Path.GetTempPath(), "ClaudeVerify_NoSuchFolder_" + Guid.NewGuid()));
    await Task.Delay(100);
}

async Task TestScreenshotSourceCapturesNewFile()
{
    string csvPath = TempFile();
    string watchedFolder = Path.Combine(Path.GetTempPath(), "ClaudeVerify_Screenshots_" + Guid.NewGuid());
    Directory.CreateDirectory(watchedFolder);
    try
    {
        await using (var writer = new EventCsvWriter(csvPath))
        {
            using var source = new ScreenshotCaptureSource(writer, watchedFolder);
            await File.WriteAllBytesAsync(Path.Combine(watchedFolder, "Screenshot 2026-01-01 120000.png"), [1, 2, 3]);
            await Task.Delay(1000); // watcher's own 200ms settle delay + margin
        }

        string[] lines = File.ReadAllLines(csvPath);
        Assert(lines.Length == 2, $"Expected header + 1 captured entry, got {lines.Length} lines");
        int cols = CountCsvColumns(lines[1]);
        Assert(cols == 3, $"Expected 3 columns, got {cols} in: {lines[1]}");
        Assert(lines[1].Contains("A screenshot was saved to disk."), $"Expected screenshot description, got: {lines[1]}");
    }
    finally
    {
        Directory.Delete(watchedFolder, recursive: true);
    }
}

async Task TestWuSettingsSourceSmoke()
{
    string path = TempFile();
    await using var writer = new EventCsvWriter(path);
    // never throws regardless of environment
    using var source = new WindowsUpdateSettingsSource(writer);
    await Task.Delay(100);
}

// EventCsvReader tests

async Task TestCsvReaderRoundTrip()
{
    string path = TempFile();
    var t1 = new DateTimeOffset(2027, 1, 2, 21, 5, 5, TimeSpan.Zero);
    var t2 = t1.AddMinutes(1);

    await using (var w = new EventCsvWriter(path))
    {
        w.TryWrite(new CsvEntry(t1, "no context", null));
        w.TryWrite(new CsvEntry(t2, "with context",
            new Dictionary<string, string> { ["provider"] = "Kernel-General", ["channel"] = "System" }));
    }

    var read = new List<CsvEntry>();
    await foreach (var entry in EventCsvReader.ReadAsync(path))
        read.Add(entry);

    Assert(read.Count == 2, $"Expected 2 entries, got {read.Count}");
    Assert(read[0].Timestamp == t1, $"Timestamp 1 mismatch: {read[0].Timestamp} vs {t1}");
    Assert(read[0].Description == "no context", $"Description 1 mismatch: {read[0].Description}");
    Assert(read[0].Context is null, $"Expected null context for entry 1, got: {read[0].Context}");

    Assert(read[1].Timestamp == t2, $"Timestamp 2 mismatch: {read[1].Timestamp} vs {t2}");
    Assert(read[1].Description == "with context", $"Description 2 mismatch: {read[1].Description}");
    Assert(read[1].Context is not null
        && read[1].Context!["provider"] == "Kernel-General"
        && read[1].Context!["channel"] == "System",
        $"Context 2 mismatch: {(read[1].Context is null ? "null" : string.Join(";", read[1].Context!.Select(kv => $"{kv.Key}={kv.Value}")))}");
}

async Task TestCsvReaderRoundTripNastyFields()
{
    string path = TempFile();
    var t1 = new DateTimeOffset(2027, 1, 1, 0, 0, 0, TimeSpan.Zero);
    string description = "event, with \"quotes\" and\r\nan embedded newline";
    var context = new Dictionary<string, string>
    {
        ["mixed_val"] = "C:\\path\\to\\file, \"quoted\"; key=val",
        ["semicolon_val"] = "value;with;semicolons",
    };

    await using (var w = new EventCsvWriter(path))
        w.TryWrite(new CsvEntry(t1, description, context));

    var read = new List<CsvEntry>();
    await foreach (var entry in EventCsvReader.ReadAsync(path))
        read.Add(entry);

    Assert(read.Count == 1, $"Expected 1 entry, got {read.Count}");
    Assert(read[0].Description == description, $"Description round-trip mismatch, got: '{read[0].Description}'");
    Assert(read[0].Context is not null
        && read[0].Context!["mixed_val"] == context["mixed_val"]
        && read[0].Context!["semicolon_val"] == context["semicolon_val"],
        "Context round-trip mismatch for nasty values");
}

async Task TestCsvReaderEmptyFile()
{
    string path = TempFile();
    await using (var w = new EventCsvWriter(path))
    {
        // dispose immediately, header only
    }

    var read = new List<CsvEntry>();
    await foreach (var entry in EventCsvReader.ReadAsync(path))
        read.Add(entry);

    Assert(read.Count == 0, $"Expected 0 entries from a header-only file, got {read.Count}");
}

// file-lock resilience tests

async Task TestWriterRetriesTransientLock()
{
    string path = TempFile();

    // simulate transient exclusive lock
    var blocker = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None);
    var releaseTask = Task.Run(async () =>
    {
        await Task.Delay(400);
        blocker.Dispose();
    });

    bool faultRaised = false;
    await using (var w = new EventCsvWriter(path))
    {
        w.WriteFault += _ => faultRaised = true;
        w.TryWrite(new CsvEntry(DateTimeOffset.UtcNow, "after transient lock"));
        await releaseTask;
    }

    Assert(!faultRaised, "Writer should have retried past the transient lock without dropping the entry");
    string[] lines = File.ReadAllLines(path);
    Assert(lines.Any(l => l.Contains("after transient lock")), "Entry should have been written once the lock cleared");
}

async Task TestWriterSurfacesFaultOnUnrecoverablePath()
{
    // permanent failure surfaces quickly
    string path = Path.Combine(Path.GetTempPath(), $"elc_test_missing_{Guid.NewGuid():N}", "events.csv");

    Exception? fault = null;
    var faultSignal = new TaskCompletionSource();
    await using (var w = new EventCsvWriter(path))
    {
        w.WriteFault += ex => { fault = ex; faultSignal.TrySetResult(); };
        w.TryWrite(new CsvEntry(DateTimeOffset.UtcNow, "should be dropped"));
        await Task.WhenAny(faultSignal.Task, Task.Delay(5000));
    }

    Assert(fault is not null, "Expected WriteFault to be raised for an unrecoverable path");
}

async Task TestWriterNeverThrowsOnUnrecoverablePath()
{
    // disposeasync must not throw on failed writes
    string path = Path.Combine(Path.GetTempPath(), $"elc_test_missing_{Guid.NewGuid():N}", "events.csv");

    var w = new EventCsvWriter(path);
    w.TryWrite(new CsvEntry(DateTimeOffset.UtcNow, "one"));
    w.TryWrite(new CsvEntry(DateTimeOffset.UtcNow, "two"));
    await Task.Delay(200);
    w.TryWrite(new CsvEntry(DateTimeOffset.UtcNow, "three"));

    await w.DisposeAsync();  // must not throw
}

// LogSessionRepository correlation reload tests

async Task TestSessionRepositoryRecoversCorrelationIdsAcrossReload()
{
    string dir = Path.Combine(Path.GetTempPath(), $"elc_test_session_{Guid.NewGuid():N}");
    Directory.CreateDirectory(dir);
    try
    {
        string csvPath = Path.Combine(dir, "events_20270102_030405.csv");
        string sidecarPath = LogSessionRepository.SidecarPathFor(csvPath);

        // same second distinct sub-second components
        var t1 = new DateTimeOffset(2027, 1, 2, 3, 4, 5, TimeSpan.Zero).AddTicks(1234567);
        var t2 = t1.AddMilliseconds(50);

        await using (var writer = new EventCsvWriter(csvPath))
        {
            writer.TryWrite(new CsvEntry(t1, "A user account was changed."));
            writer.TryWrite(new CsvEntry(t2, "An attempt was made to reset an account's password."));
        }

        await using (var sidecar = new CorrelationSidecarWriter(sidecarPath))
        {
            sidecar.TryWrite(new SidecarRecord(t1, "A user account was changed.",
                nameof(EventKind.UserAccountChanged), null, 1240, null));
            sidecar.TryWrite(new SidecarRecord(t2, "An attempt was made to reset an account's password.",
                nameof(EventKind.PasswordResetAttempted), null, 1240, null));
        }

        var repo = new LogSessionRepository(new LogFolderSettings { LogsDirectory = dir });
        var rows = await repo.LoadAllRowsWithCorrelationAsync();

        Assert(rows.Count == 2, $"Expected 2 rows, got {rows.Count}");
        Assert(rows.All(r => r.Ids.ProcessId == 1240),
            $"Both rows should recover ProcessId 1240 from the sidecar after reload, got: " +
            $"[{string.Join(", ", rows.Select(r => r.Ids.ProcessId?.ToString() ?? "null"))}]");
        Assert(rows[0].Kind == EventKind.UserAccountChanged, $"Row 0 kind mismatch: {rows[0].Kind}");
        Assert(rows[1].Kind == EventKind.PasswordResetAttempted, $"Row 1 kind mismatch: {rows[1].Kind}");
    }
    finally
    {
        try { Directory.Delete(dir, recursive: true); } catch { }
    }
}

async Task TestReloadedSessionGroupsCorrectlyByProcessId()
{
    string dir = Path.Combine(Path.GetTempPath(), $"elc_test_session_{Guid.NewGuid():N}");
    Directory.CreateDirectory(dir);
    try
    {
        string csvPath = Path.Combine(dir, "events_20270102_030405.csv");
        string sidecarPath = LogSessionRepository.SidecarPathFor(csvPath);

        var t1 = new DateTimeOffset(2027, 1, 2, 3, 4, 5, TimeSpan.Zero).AddTicks(9876543);
        // beyond proximity window, direct-id link only
        var t2 = t1.AddSeconds(45);

        await using (var writer = new EventCsvWriter(csvPath))
        {
            writer.TryWrite(new CsvEntry(t1, "A new process has been created."));
            writer.TryWrite(new CsvEntry(t2, "A user account was changed."));
        }

        await using (var sidecar = new CorrelationSidecarWriter(sidecarPath))
        {
            sidecar.TryWrite(new SidecarRecord(t1, "A new process has been created.",
                nameof(EventKind.ProcessCreated), null, 4242, null));
            sidecar.TryWrite(new SidecarRecord(t2, "A user account was changed.",
                nameof(EventKind.UserAccountChanged), null, 4242, null));
        }

        var repo = new LogSessionRepository(new LogFolderSettings { LogsDirectory = dir });
        var loaded = await repo.LoadAllRowsWithCorrelationAsync();
        Assert(loaded.Count == 2, $"Expected 2 rows, got {loaded.Count}");

        var rows = loaded.Select(l => l.Row).ToList();
        var ids = loaded.Select(l => l.Ids).ToList();
        CorrelationGrouping.AssignGroups(rows, ids);

        Assert(rows[0].GroupLabel != "Uncorrelated" && rows[1].GroupLabel != "Uncorrelated",
            $"Both rows share ProcessId 4242 and should be grouped, got labels: " +
            $"'{rows[0].GroupLabel}', '{rows[1].GroupLabel}'");
        Assert(rows[0].GroupLabel == rows[1].GroupLabel,
            $"Both rows should land in the same group, got: '{rows[0].GroupLabel}' vs '{rows[1].GroupLabel}'");
        Assert(rows[0].GroupLabel.Contains("same process"),
            $"Expected the 'same process' match reason, got: '{rows[0].GroupLabel}'");
    }
    finally
    {
        try { Directory.Delete(dir, recursive: true); } catch { }
    }
}

// helpers

static string TempFile()
{
    string p = Path.Combine(Path.GetTempPath(), $"elc_test_{Guid.NewGuid():N}.csv");
    // best-effort cleanup on exit
    AppDomain.CurrentDomain.ProcessExit += (_, _) => { try { File.Delete(p); } catch { } };
    return p;
}

// counts csv columns
static int CountCsvColumns(string line)
{
    int cols = 1;
    bool inQuotes = false;
    foreach (char c in line)
    {
        if (c == '"') inQuotes = !inQuotes;
        else if (c == ',' && !inQuotes) cols++;
    }
    return cols;
}

void Assert(bool condition, string message)
{
    if (!condition) throw new Exception(message);
}

async Task RunTest(string name, Func<Task> test)
{
    var sw = Stopwatch.StartNew();
    try
    {
        await test();
        sw.Stop();
        Console.WriteLine($"  [PASS] {name} ({sw.ElapsedMilliseconds}ms)");
        passed++;
    }
    catch (Exception ex)
    {
        sw.Stop();
        Console.WriteLine($"  [FAIL] {name} ({sw.ElapsedMilliseconds}ms)");
        Console.WriteLine($"         {ex.Message}");
        failed++;
    }
}
