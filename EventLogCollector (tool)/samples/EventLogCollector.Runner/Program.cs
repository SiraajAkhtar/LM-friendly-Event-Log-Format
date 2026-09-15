using EventLogCollector;

var outputPath = Path.Combine(
    Directory.GetCurrentDirectory(),
    $"events_{DateTime.Now:yyyyMMdd_HHmmss}.csv");

Console.WriteLine("EventLogCollector — live capture");
Console.WriteLine($"Output : {outputPath}");
Console.WriteLine("Sources: System | Security | TerminalServices | Application | NetworkProfile | DHCP | WLAN");
Console.WriteLine();

await using var writer = new EventCsvWriter(outputPath);
using var osSource  = new OsEventLogSource(writer);
using var appSource = new AppEventLogSource(writer);
using var netSource = new NetworkEventLogSource(writer);

Console.WriteLine("Listening for events... Press Ctrl+C or Enter to stop.");

using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

// live file size indicator
var ticker = Task.Run(async () =>
{
    while (!cts.IsCancellationRequested)
    {
        try
        {
            long size = new FileInfo(outputPath).Length;
            Console.Write($"\r  [{DateTime.Now:HH:mm:ss}]  {size,8:N0} bytes written   ");
        }
        catch { }

        try { await Task.Delay(1000, cts.Token); }
        catch (OperationCanceledException) { break; }
    }
}, CancellationToken.None);

await Task.Run(() => { Console.ReadLine(); cts.Cancel(); });
await ticker;

Console.WriteLine();
Console.WriteLine("Stopped. CSV saved to:");
Console.WriteLine($"  {outputPath}");
