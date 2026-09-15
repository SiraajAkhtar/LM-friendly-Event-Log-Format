using System.IO;
using System.Text.Json;

namespace EventLogCollector.Gui.Services;

// user log folder setting
internal sealed class LogFolderSettings
{
    private static string SettingsFilePath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "EventLogCollector", "settings.json");

    public static string DefaultLogsDirectory => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "EventLogCollector", "logs");

    public string LogsDirectory { get; set; } = DefaultLogsDirectory;

    public static LogFolderSettings LoadOrDefault()
    {
        try
        {
            string json = File.ReadAllText(SettingsFilePath);
            var loaded = JsonSerializer.Deserialize<LogFolderSettings>(json);
            if (loaded is not null && !string.IsNullOrWhiteSpace(loaded.LogsDirectory))
                return loaded;
        }
        catch
        {
            // missing or corrupt, use default
        }

        return new LogFolderSettings();
    }

    public void Save()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(SettingsFilePath)!);
        File.WriteAllText(SettingsFilePath, JsonSerializer.Serialize(this));
    }
}
