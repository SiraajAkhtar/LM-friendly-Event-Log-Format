using System.IO;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using EventLogCollector.Gui.Services;
using Microsoft.Win32;

namespace EventLogCollector.Gui.ViewModels;

// page 1, start/stop recording and status
internal partial class RecordingViewModel : ObservableObject, IDisposable
{
    private readonly RecordingSessionService _session;
    private readonly LogFolderSettings _settings;
    private CancellationTokenSource? _pollCts;
    private Task? _pollTask;

    [ObservableProperty]
    private bool isRecording;

    [ObservableProperty]
    private string statusText = "Idle — not recording.";

    [ObservableProperty]
    private long bytesRecorded;

    [ObservableProperty]
    private int droppedWriteCount;

    [ObservableProperty]
    private string logsDirectory;

    [ObservableProperty]
    private string logsDirectoryStatus = string.Empty;

    [ObservableProperty]
    private bool isLogsDirectoryValid = true;

    [ObservableProperty]
    private bool canEditLogsDirectory = true;

    public RecordingViewModel(RecordingSessionService session, LogFolderSettings settings)
    {
        _session = session;
        _settings = settings;
        _session.WriteFault += OnWriteFault;

        logsDirectory = settings.LogsDirectory;
        _ = ValidateLogsDirectoryAsync();
    }

    private void OnWriteFault(Exception ex) => _ = UiThread.RunAsync(() => DroppedWriteCount++);

    private bool CanStart() => !IsRecording && IsLogsDirectoryValid;
    private bool CanStop() => IsRecording;
    private bool CanEditLogsDirectoryNow() => !IsRecording;

    partial void OnIsRecordingChanged(bool value)
    {
        CanEditLogsDirectory = CanEditLogsDirectoryNow();
        BrowseLogsDirectoryCommand.NotifyCanExecuteChanged();
    }

    partial void OnLogsDirectoryChanged(string value)
    {
        _settings.LogsDirectory = value;
        _settings.Save();
        _ = ValidateLogsDirectoryAsync();
    }

    [RelayCommand(CanExecute = nameof(CanEditLogsDirectoryNow))]
    private void BrowseLogsDirectory()
    {
        var dialog = new OpenFolderDialog
        {
            Title = "Choose where session logs are saved",
            InitialDirectory = Directory.Exists(LogsDirectory) ? LogsDirectory : LogFolderSettings.DefaultLogsDirectory,
        };

        if (dialog.ShowDialog() == true)
            LogsDirectory = dialog.FolderName;
    }

    private async Task ValidateLogsDirectoryAsync()
    {
        string target = LogsDirectory;
        string? failure = await Task.Run(() => FolderAccessCheck.TryEnsureWritable(target)).ConfigureAwait(true);

        IsLogsDirectoryValid = failure is null;
        LogsDirectoryStatus = failure is null
            ? "Folder is writable."
            : $"Can't write to this folder: {failure}";

        StartCommand.NotifyCanExecuteChanged();
    }

    [RelayCommand(CanExecute = nameof(CanStart))]
    private async Task StartAsync()
    {
        // re-check folder before starting
        string? failure = await Task.Run(() => FolderAccessCheck.TryEnsureWritable(LogsDirectory)).ConfigureAwait(true);
        if (failure is not null)
        {
            IsLogsDirectoryValid = false;
            LogsDirectoryStatus = $"Can't write to this folder: {failure}";
            StartCommand.NotifyCanExecuteChanged();
            return;
        }

        await _session.StartAsync().ConfigureAwait(true);

        IsRecording = true;
        BytesRecorded = 0;
        DroppedWriteCount = 0;
        StatusText = $"Recording to {Path.GetFileName(_session.CurrentCsvPath)}...";

        StartCommand.NotifyCanExecuteChanged();
        StopCommand.NotifyCanExecuteChanged();
        BrowseLogsDirectoryCommand.NotifyCanExecuteChanged();

        _pollCts = new CancellationTokenSource();
        _pollTask = Task.Run(() => PollBytesAsync(_pollCts.Token));
    }

    [RelayCommand(CanExecute = nameof(CanStop))]
    private async Task StopAsync()
    {
        _pollCts?.Cancel();
        if (_pollTask is not null)
        {
            try { await _pollTask.ConfigureAwait(true); }
            catch (OperationCanceledException) { }
        }

        string? savedPath = _session.CurrentCsvPath;
        await _session.StopAsync().ConfigureAwait(true);

        IsRecording = false;
        StatusText = savedPath is null
            ? "Idle — not recording."
            : $"Stopped. Saved to {Path.GetFileName(savedPath)}.";

        StartCommand.NotifyCanExecuteChanged();
        StopCommand.NotifyCanExecuteChanged();
        BrowseLogsDirectoryCommand.NotifyCanExecuteChanged();
    }

    private async Task PollBytesAsync(CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                long bytes = _session.GetBytesWritten();
                int dropped = DroppedWriteCount;
                await UiThread.RunAsync(() =>
                {
                    BytesRecorded = bytes;
                    StatusText = dropped == 0
                        ? $"Recording... {bytes:N0} bytes written."
                        : $"Recording... {bytes:N0} bytes written. ({dropped} write(s) dropped — check antivirus/cloud sync)";
                }).ConfigureAwait(false);

                await Task.Delay(500, ct).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
            // expected on stop
        }
    }

    public void Dispose()
    {
        _session.WriteFault -= OnWriteFault;
        _pollCts?.Cancel();
        _pollCts?.Dispose();
    }
}
