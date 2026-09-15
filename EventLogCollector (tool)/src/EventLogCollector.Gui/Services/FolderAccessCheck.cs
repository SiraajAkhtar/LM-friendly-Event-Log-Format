using System.IO;

namespace EventLogCollector.Gui.Services;

// checks folder is writable
internal static class FolderAccessCheck
{
    // probe write then delete
    public static string? TryEnsureWritable(string directoryPath)
    {
        try
        {
            Directory.CreateDirectory(directoryPath);
            string probePath = Path.Combine(directoryPath, $".write-check_{Guid.NewGuid():N}.tmp");
            File.WriteAllBytes(probePath, [0]);
            File.Delete(probePath);
            return null;
        }
        catch (Exception ex)
        {
            return ex.Message;
        }
    }
}
