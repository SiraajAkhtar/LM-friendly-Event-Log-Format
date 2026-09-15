using System.Windows;

namespace EventLogCollector.Gui.Services;

// marshals callback to ui thread
internal static class UiThread
{
    public static Task RunAsync(Action action)
    {
        var dispatcher = Application.Current?.Dispatcher;
        if (dispatcher is null || dispatcher.CheckAccess())
        {
            action();
            return Task.CompletedTask;
        }

        return dispatcher.InvokeAsync(action).Task;
    }
}
