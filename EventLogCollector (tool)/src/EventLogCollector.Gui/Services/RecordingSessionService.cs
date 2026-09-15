using System.IO;
using EventLogCollector;
using EventLogCollector.Gui.Models;

namespace EventLogCollector.Gui.Services;

// owns one recording session
internal sealed class RecordingSessionService(LogFolderSettings settings)
{
    private EventCsvWriter? _writer;
    private CorrelationSidecarWriter? _sidecarWriter;
    private OsEventLogSource? _osSource;
    private NetworkEventLogSource? _networkSource;
    private AppEventLogSource? _appSource;
    private ScreenshotCaptureSource? _screenshotSource;
    private WindowsUpdateSettingsSource? _wuSettingsSource;

    public string? CurrentCsvPath { get; private set; }
    public bool IsRecording => _writer is not null;

    // fired per captured event
    public event Action<LogEntryRow, EventKind, CorrelationIds>? EntryCaptured;

    // fired on dropped write
    public event Action<Exception>? WriteFault;

    public Task StartAsync() => Task.Run(() =>
    {
        if (IsRecording) return;

        string logsDirectory = settings.LogsDirectory;
        Directory.CreateDirectory(logsDirectory);
        string baseName = $"events_{DateTime.Now:yyyyMMdd_HHmmss}";
        string csvPath = Path.Combine(logsDirectory, $"{baseName}.csv");
        string sidecarPath = LogSessionRepository.SidecarPathFor(csvPath);

        CurrentCsvPath = csvPath;
        _writer = new EventCsvWriter(csvPath);
        _sidecarWriter = new CorrelationSidecarWriter(sidecarPath);

        _writer.WriteFault += OnWriteFault;
        _sidecarWriter.WriteFault += OnWriteFault;

        _osSource = new OsEventLogSource(_writer);
        _networkSource = new NetworkEventLogSource(_writer);
        _appSource = new AppEventLogSource(_writer);
        _screenshotSource = new ScreenshotCaptureSource(_writer);
        _wuSettingsSource = new WindowsUpdateSettingsSource(_writer);

        _osSource.EntryCaptured += OnCaptured;
        _networkSource.EntryCaptured += OnCaptured;
        _appSource.EntryCaptured += OnCaptured;
        _screenshotSource.EntryCaptured += OnCaptured;
        _wuSettingsSource.EntryCaptured += OnCaptured;
    });

    public long GetBytesWritten()
    {
        if (CurrentCsvPath is null)
            return 0;

        try { return new FileInfo(CurrentCsvPath).Length; }
        catch { return 0; }
    }

    public async Task StopAsync()
    {
        if (!IsRecording) return;

        if (_osSource is not null) _osSource.EntryCaptured -= OnCaptured;
        if (_networkSource is not null) _networkSource.EntryCaptured -= OnCaptured;
        if (_appSource is not null) _appSource.EntryCaptured -= OnCaptured;
        if (_screenshotSource is not null) _screenshotSource.EntryCaptured -= OnCaptured;
        if (_wuSettingsSource is not null) _wuSettingsSource.EntryCaptured -= OnCaptured;

        _osSource?.Dispose();
        _networkSource?.Dispose();
        _appSource?.Dispose();
        _screenshotSource?.Dispose();
        _wuSettingsSource?.Dispose();

        if (_writer is not null)
        {
            _writer.WriteFault -= OnWriteFault;
            await _writer.DisposeAsync().ConfigureAwait(false);
        }
        if (_sidecarWriter is not null)
        {
            _sidecarWriter.WriteFault -= OnWriteFault;
            await _sidecarWriter.DisposeAsync().ConfigureAwait(false);
        }

        _writer = null;
        _sidecarWriter = null;
        _osSource = null;
        _networkSource = null;
        _appSource = null;
        _screenshotSource = null;
        _wuSettingsSource = null;
    }

    private void OnWriteFault(Exception ex) => WriteFault?.Invoke(ex);

    private void OnCaptured(CapturedEntry captured)
    {
        _sidecarWriter?.TryWrite(new SidecarRecord(
            captured.Entry.Timestamp,
            captured.Entry.Description,
            captured.Kind.ToString(),
            captured.Ids.LogonId,
            captured.Ids.ProcessId,
            captured.Ids.InterfaceGuid));

        var row = new LogEntryRow
        {
            Timestamp = captured.Entry.Timestamp,
            Description = captured.Entry.Description,
            ContextDict = captured.Entry.Context,
            SourceFilePath = CurrentCsvPath ?? string.Empty,
        };

        EntryCaptured?.Invoke(row, captured.Kind, captured.Ids);
    }
}
