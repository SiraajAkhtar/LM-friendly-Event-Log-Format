using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using EventLogCollector.Gui.Services;

namespace EventLogCollector.Gui.ViewModels;

// owns the three page view models
internal partial class MainViewModel : ObservableObject
{
    private readonly LogFolderSettings _settings = LogFolderSettings.LoadOrDefault();
    private readonly RecordingSessionService _session;

    [ObservableProperty]
    private int selectedPageIndex;

    public RecordingViewModel Recording { get; }
    public LiveLogsViewModel LiveLogs { get; }
    public CorrelatedLogsViewModel CorrelatedLogs { get; }

    public MainViewModel()
    {
        _session = new RecordingSessionService(_settings);
        Recording = new RecordingViewModel(_session, _settings);
        LiveLogs = new LiveLogsViewModel(_session, _settings);
        CorrelatedLogs = new CorrelatedLogsViewModel(_session, _settings);

        _ = LiveLogs.LoadAsync();
        _ = CorrelatedLogs.LoadAsync();
    }

    [RelayCommand]
    private void NavigateTo(string pageIndex) => SelectedPageIndex = int.Parse(pageIndex);
}
