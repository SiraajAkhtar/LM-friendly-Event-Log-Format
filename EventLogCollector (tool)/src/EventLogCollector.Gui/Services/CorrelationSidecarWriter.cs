using System.IO;
using System.Text;
using System.Text.Json;
using System.Threading.Channels;
using EventLogCollector;

namespace EventLogCollector.Gui.Services;

// one sidecar ndjson line
internal sealed record SidecarRecord(
    DateTimeOffset Timestamp,
    string Description,
    string Kind,
    string? LogonId,
    int? ProcessId,
    string? InterfaceGuid);

// appends sidecar ndjson lines
internal sealed class CorrelationSidecarWriter : IAsyncDisposable
{
    private readonly Channel<SidecarRecord> _channel;
    private readonly Task _drainTask;

    public CorrelationSidecarWriter(string filePath)
    {
        _channel = Channel.CreateUnbounded<SidecarRecord>(new UnboundedChannelOptions
        {
            SingleReader = true,
            AllowSynchronousContinuations = false
        });

        _drainTask = Task.Run(() => DrainAsync(filePath, _channel.Reader, ex => WriteFault?.Invoke(ex)));
    }

    public bool TryWrite(SidecarRecord record) => _channel.Writer.TryWrite(record);

    // raised when a line is dropped
    public event Action<Exception>? WriteFault;

    public async ValueTask DisposeAsync()
    {
        _channel.Writer.Complete();
        await _drainTask.ConfigureAwait(false);
    }

    private static async Task DrainAsync(string filePath, ChannelReader<SidecarRecord> reader, Action<Exception> onWriteFault)
    {
        FileStream stream;
        try
        {
            stream = await FileWriteResilience.RetryAsync(() => Task.FromResult(new FileStream(
                filePath, FileMode.Append, FileAccess.Write, FileShare.Read, bufferSize: 65_536, useAsync: true))).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            onWriteFault(ex);
            await foreach (var _ in reader.ReadAllAsync().ConfigureAwait(false))
                onWriteFault(ex);
            return;
        }

        await using (stream)
        {
            await foreach (var record in reader.ReadAllAsync().ConfigureAwait(false))
            {
                byte[] bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(record) + "\n");
                try
                {
                    await FileWriteResilience.RetryAsync(async () =>
                    {
                        await stream.WriteAsync(bytes).ConfigureAwait(false);
                        await stream.FlushAsync().ConfigureAwait(false);
                        return true;
                    }).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    onWriteFault(ex);
                }
            }
        }
    }
}
