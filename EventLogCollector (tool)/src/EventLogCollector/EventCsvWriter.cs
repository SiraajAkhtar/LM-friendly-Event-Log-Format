using System.Text;
using System.Threading.Channels;

namespace EventLogCollector;

// single-writer, lock-free csv writer
public sealed class EventCsvWriter : IAsyncDisposable
{
    private readonly Channel<CsvEntry> _channel;
    private readonly Task _drainTask;

    public EventCsvWriter(string filePath)
    {
        // unbounded single-reader channel
        _channel = Channel.CreateUnbounded<CsvEntry>(new UnboundedChannelOptions
        {
            SingleReader = true,
            AllowSynchronousContinuations = false  // resume on thread-pool
        });

        _drainTask = Task.Run(() => DrainAsync(filePath, _channel.Reader, ex => WriteFault?.Invoke(ex)));
    }

    // fire-and-forget enqueue
    public bool TryWrite(CsvEntry entry) => _channel.Writer.TryWrite(entry);

    // async enqueue
    public ValueTask WriteAsync(CsvEntry entry, CancellationToken ct = default)
        => _channel.Writer.WriteAsync(entry, ct);

    // dropped-write notification
    public event Action<Exception>? WriteFault;

    // flush and close
    public async ValueTask DisposeAsync()
    {
        _channel.Writer.Complete();
        await _drainTask.ConfigureAwait(false);
    }

    // drain loop

    private static async Task DrainAsync(string filePath, ChannelReader<CsvEntry> reader, Action<Exception> onWriteFault)
    {
        bool isNewFile = !File.Exists(filePath) || new FileInfo(filePath).Length == 0;

        FileStream stream;
        try
        {
            stream = await FileWriteResilience.RetryAsync(() => Task.FromResult(new FileStream(
                filePath,
                FileMode.Append,
                FileAccess.Write,
                FileShare.Read,       // concurrent readers allowed
                bufferSize: 65_536,
                useAsync: true))).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            // file never opened, drain and report every entry
            onWriteFault(ex);
            await foreach (var _ in reader.ReadAllAsync().ConfigureAwait(false))
                onWriteFault(ex);
            return;
        }

        await using (stream)
        {
            if (isNewFile)
                await WriteLineAsync(stream, "Timestamp,Description,Context", onWriteFault).ConfigureAwait(false);

            await foreach (var entry in reader.ReadAllAsync().ConfigureAwait(false))
            {
                string context = entry.Context is { Count: > 0 }
                    ? CsvFormat.SerializeContext(entry.Context)
                    : string.Empty;

                string line = $"{CsvFormat.Escape(entry.Timestamp.ToString(CsvFormat.TimestampFormat))},{CsvFormat.Escape(entry.Description)},{CsvFormat.Escape(context)}";
                await WriteLineAsync(stream, line, onWriteFault).ConfigureAwait(false);
            }
        }
    }

    // writes one line's raw bytes, retryable as a unit
    private static async Task WriteLineAsync(FileStream stream, string line, Action<Exception> onWriteFault)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(line + "\n");
        try
        {
            // flush after every entry
            await FileWriteResilience.RetryAsync(async () =>
            {
                await stream.WriteAsync(bytes).ConfigureAwait(false);
                await stream.FlushAsync().ConfigureAwait(false);
                return true;
            }).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            // retries exhausted, drop the line
            onWriteFault(ex);
        }
    }
}
