namespace EventLogCollector;

// watches screenshots folder, no event log entry exists for this
public sealed class ScreenshotCaptureSource : IDisposable
{
    private readonly EventCsvWriter _writer;
    private readonly FileSystemWatcher? _watcher;

    internal event Action<CapturedEntry>? EntryCaptured;

    // folder overrides pictures\screenshots
    public ScreenshotCaptureSource(EventCsvWriter writer, string? folder = null)
    {
        _writer = writer;

        string screenshotsFolder = folder ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.MyPictures), "Screenshots");

        try
        {
            if (!Directory.Exists(screenshotsFolder))
                return; // nothing to watch yet

            _watcher = new FileSystemWatcher(screenshotsFolder)
            {
                Filter = "*.png",
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite,
            };
            _watcher.Created += OnFileCreated;
            _watcher.EnableRaisingEvents = true;
        }
        catch
        {
            // folder inaccessible, skip
            _watcher?.Dispose();
            _watcher = null;
        }
    }

    public void Dispose()
    {
        if (_watcher is null) return;
        _watcher.EnableRaisingEvents = false;
        _watcher.Created -= OnFileCreated;
        _watcher.Dispose();
    }

    private void OnFileCreated(object sender, FileSystemEventArgs e)
    {
        // let write finish flushing
        Thread.Sleep(200);

        DateTimeOffset timestamp;
        try { timestamp = new DateTimeOffset(File.GetLastWriteTimeUtc(e.FullPath), TimeSpan.Zero); }
        catch { timestamp = DateTimeOffset.UtcNow; } // file already gone

        var context = new Dictionary<string, string>
        {
            ["source"]   = "ScreenshotCaptureSource",
            ["fileName"] = e.Name ?? Path.GetFileName(e.FullPath),
            ["folder"]   = Path.GetDirectoryName(e.FullPath) ?? string.Empty,
        };

        var entry = new CsvEntry(timestamp, "A screenshot was saved to disk.", context);

        _writer.TryWrite(entry);
        EntryCaptured?.Invoke(new CapturedEntry(entry, EventKind.ScreenshotCaptured, default));
    }
}
