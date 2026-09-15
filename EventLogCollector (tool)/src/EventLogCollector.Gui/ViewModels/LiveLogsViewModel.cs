using System.Collections.ObjectModel;
using EventLogCollector;
using EventLogCollector.Gui.Models;
using EventLogCollector.Gui.Services;

namespace EventLogCollector.Gui.ViewModels;

// page 2, all sessions merged
internal sealed partial class LiveLogsViewModel : LogsViewModelBase
{
    private readonly RecordingSessionService _session;

    public LiveLogsViewModel(RecordingSessionService session, LogFolderSettings settings) : base(settings)
    {
        _session = session;
        _session.EntryCaptured += OnEntryCaptured;
    }

    protected override async Task LoadCoreAsync()
    {
        // current recording excluded from disk scan
        var rows = await Repository.LoadAllRowsAsync(_session.CurrentCsvPath).ConfigureAwait(true);
        Entries = new ObservableCollection<LogEntryRow>(rows);
    }

    private void OnEntryCaptured(LogEntryRow row, EventKind kind, CorrelationIds ids)
        => _ = UiThread.RunAsync(() => Entries.Add(row));
}
