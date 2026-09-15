using System.Collections.ObjectModel;
using EventLogCollector;
using EventLogCollector.Gui.Models;
using EventLogCollector.Gui.Services;

namespace EventLogCollector.Gui.ViewModels;

// page 3, rows grouped by correlation
internal sealed partial class CorrelatedLogsViewModel : LogsViewModelBase
{
    private readonly RecordingSessionService _session;
    private readonly List<(LogEntryRow Row, CorrelationIds Ids)> _liveBuffer = [];
    private readonly object _liveBufferLock = new();
    private List<(LogEntryRow Row, CorrelationIds Ids)> _historicalCache = [];

    public CorrelatedLogsViewModel(RecordingSessionService session, LogFolderSettings settings) : base(settings)
    {
        _session = session;
        _session.EntryCaptured += OnEntryCaptured;
    }

    protected override async Task LoadCoreAsync()
    {
        var historical = await Repository.LoadAllRowsWithCorrelationAsync(_session.CurrentCsvPath).ConfigureAwait(true);
        _historicalCache = historical.Select(h => (h.Row, h.Ids)).ToList();
        RebuildEntries();
    }

    private void OnEntryCaptured(LogEntryRow row, EventKind kind, CorrelationIds ids)
    {
        lock (_liveBufferLock)
            _liveBuffer.Add((row, ids));

        _ = UiThread.RunAsync(RebuildEntries);
    }

    private void RebuildEntries()
    {
        List<(LogEntryRow Row, CorrelationIds Ids)> live;
        lock (_liveBufferLock)
            live = [.. _liveBuffer];

        var combined = _historicalCache
            .Concat(live)
            .OrderBy(x => x.Row.Timestamp)
            .ToList();

        var rows = combined.Select(x => x.Row).ToList();
        var ids = combined.Select(x => x.Ids).ToList();
        CorrelationGrouping.AssignGroups(rows, ids);

        Entries = new ObservableCollection<LogEntryRow>(rows);
    }
}
