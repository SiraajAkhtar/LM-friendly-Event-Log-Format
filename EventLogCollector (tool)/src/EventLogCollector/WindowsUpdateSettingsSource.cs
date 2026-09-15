using System.Management;
using Microsoft.Win32;

namespace EventLogCollector;

// tracked windows update registry settings
internal readonly record struct WindowsUpdateSettingsSnapshot(
    int? ActiveHoursStart,
    int? ActiveHoursEnd,
    bool PauseUpdatesActive,
    int? AllowAutoWindowsUpdateDownloadOverMeteredNetwork)
{
    public static WindowsUpdateSettingsSnapshot Read(RegistryKey settingsKey) => new(
        ActiveHoursStart: settingsKey.GetValue("ActiveHoursStart") as int?,
        ActiveHoursEnd: settingsKey.GetValue("ActiveHoursEnd") as int?,
        // presence of the value is the on/off signal
        PauseUpdatesActive: settingsKey.GetValue("PauseUpdatesExpiryTime") is not null,
        AllowAutoWindowsUpdateDownloadOverMeteredNetwork:
            settingsKey.GetValue("AllowAutoWindowsUpdateDownloadOverMeteredNetwork") as int?);

    // pure diff, only changed fields
    public static Dictionary<string, string> Diff(WindowsUpdateSettingsSnapshot before, WindowsUpdateSettingsSnapshot after)
    {
        var changed = new Dictionary<string, string>();

        void Compare<T>(string name, T? oldValue, T? newValue)
        {
            if (!Equals(oldValue, newValue))
                changed[name] = $"{Format(oldValue)} -> {Format(newValue)}";
        }

        static string Format<T>(T? value) => value is null ? "(not set)" : value.ToString() ?? "(not set)";

        Compare("ActiveHoursStart", before.ActiveHoursStart, after.ActiveHoursStart);
        Compare("ActiveHoursEnd", before.ActiveHoursEnd, after.ActiveHoursEnd);
        Compare("PauseUpdatesActive", before.PauseUpdatesActive, after.PauseUpdatesActive);
        Compare("AllowAutoWindowsUpdateDownloadOverMeteredNetwork",
            before.AllowAutoWindowsUpdateDownloadOverMeteredNetwork,
            after.AllowAutoWindowsUpdateDownloadOverMeteredNetwork);

        return changed;
    }
}

// watches the update settings registry key via wmi
public sealed class WindowsUpdateSettingsSource : IDisposable
{
    private const string SettingsKeyPath = @"SOFTWARE\Microsoft\WindowsUpdate\UX\Settings";

    private readonly EventCsvWriter _writer;
    private readonly ManagementEventWatcher? _watcher;
    private WindowsUpdateSettingsSnapshot _lastKnown;

    internal event Action<CapturedEntry>? EntryCaptured;

    public WindowsUpdateSettingsSource(EventCsvWriter writer)
    {
        _writer = writer;

        try
        {
            using var initialKey = Registry.LocalMachine.OpenSubKey(SettingsKeyPath);
            if (initialKey is null) return; // key missing, nothing to watch
            _lastKnown = WindowsUpdateSettingsSnapshot.Read(initialKey);

            var query = new WqlEventQuery(
                "RegistryKeyChangeEvent",
                TimeSpan.FromSeconds(1),
                $"Hive='HKEY_LOCAL_MACHINE' AND KeyPath='{SettingsKeyPath.Replace(@"\", @"\\")}'");
            _watcher = new ManagementEventWatcher(query);
            _watcher.EventArrived += OnRegistryKeyChanged;
            _watcher.Start();
        }
        catch
        {
            // wmi unavailable or access denied, skip
            _watcher?.Dispose();
            _watcher = null;
        }
    }

    public void Dispose()
    {
        if (_watcher is null) return;
        try { _watcher.Stop(); } catch { /* best effort */ }
        _watcher.EventArrived -= OnRegistryKeyChanged;
        _watcher.Dispose();
    }

    private void OnRegistryKeyChanged(object sender, EventArrivedEventArgs e)
    {
        WindowsUpdateSettingsSnapshot current;
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(SettingsKeyPath);
            if (key is null) return;
            current = WindowsUpdateSettingsSnapshot.Read(key);
        }
        catch
        {
            return; // best effort
        }

        var changed = WindowsUpdateSettingsSnapshot.Diff(_lastKnown, current);
        _lastKnown = current;
        if (changed.Count == 0)
            return; // nothing tracked changed

        var context = new Dictionary<string, string>(changed) { ["source"] = "WindowsUpdateSettingsSource" };
        var entry = new CsvEntry(DateTimeOffset.UtcNow, "A Windows Update setting was changed.", context);

        _writer.TryWrite(entry);
        EntryCaptured?.Invoke(new CapturedEntry(entry, EventKind.WindowsUpdateSettingChanged, default));
    }
}
