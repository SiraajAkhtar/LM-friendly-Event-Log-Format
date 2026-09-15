using System.Collections.ObjectModel;
using System.Diagnostics;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using EventLogCollector.Gui.Models;
using EventLogCollector.Gui.Services;

namespace EventLogCollector.Gui.ViewModels;

// shared grid/details behaviour for pages 2 and 3
internal abstract partial class LogsViewModelBase : ObservableObject
{
    protected readonly LogSessionRepository Repository;

    protected LogsViewModelBase(LogFolderSettings settings)
    {
        Repository = new LogSessionRepository(settings);
    }

    [ObservableProperty]
    private ObservableCollection<LogEntryRow> entries = [];

    [ObservableProperty]
    private LogEntryRow? selectedEntry;

    [ObservableProperty]
    private ObservableCollection<DetailRow> detailRows = [];

    [ObservableProperty]
    private bool isLoading;

    partial void OnSelectedEntryChanged(LogEntryRow? value)
    {
        var rows = new ObservableCollection<DetailRow>();
        if (value is not null)
        {
            rows.Add(new DetailRow("Timestamp", value.LocalTimestamp.ToString("d/M/yy HH:mm:ss"), "Timestamp"));
            rows.Add(new DetailRow("Description", value.Description, "Description"));
            if (value.ContextDict is { Count: > 0 })
                foreach (var kv in value.ContextDict)
                    rows.Add(new DetailRow(kv.Key, LogEntryRow.SingleLine(kv.Value), "Context"));
        }
        DetailRows = rows;
    }

    [RelayCommand]
    private Task OpenFileLocationAsync()
    {
        string? path = SelectedEntry?.SourceFilePath;
        if (string.IsNullOrEmpty(path))
            return Task.CompletedTask;

        return Task.Run(() =>
        {
            try { Process.Start("explorer.exe", $"/select,\"{path}\""); }
            catch { /* best-effort */ }
        });
    }

    [RelayCommand]
    public async Task LoadAsync()
    {
        IsLoading = true;
        try
        {
            await LoadCoreAsync().ConfigureAwait(true);
        }
        finally
        {
            IsLoading = false;
        }
    }

    protected abstract Task LoadCoreAsync();
}
