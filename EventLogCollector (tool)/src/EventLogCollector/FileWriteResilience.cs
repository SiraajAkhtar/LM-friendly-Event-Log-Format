namespace EventLogCollector;

// retries a file op on transient locks
internal static class FileWriteResilience
{
    private const int MaxAttempts = 6;
    private static readonly TimeSpan InitialDelay = TimeSpan.FromMilliseconds(50);
    private static readonly TimeSpan MaxDelay = TimeSpan.FromSeconds(2);

    // transient file lock codes
    private const int ErrorSharingViolation = unchecked((int)0x80070020);
    private const int ErrorLockViolation = unchecked((int)0x80070021);
    private const int ErrorAccessDenied = unchecked((int)0x80070005);

    public static async Task<T> RetryAsync<T>(Func<Task<T>> operation, CancellationToken ct = default)
    {
        TimeSpan delay = InitialDelay;
        for (int attempt = 1; ; attempt++)
        {
            try
            {
                return await operation().ConfigureAwait(false);
            }
            catch (Exception ex) when (attempt < MaxAttempts && IsTransientFileLock(ex))
            {
                await Task.Delay(delay, ct).ConfigureAwait(false);
                delay = TimeSpan.FromMilliseconds(Math.Min(delay.TotalMilliseconds * 2, MaxDelay.TotalMilliseconds));
            }
        }
    }

    private static bool IsTransientFileLock(Exception ex)
    {
        if (ex is not IOException && ex is not UnauthorizedAccessException)
            return false;

        return ex.HResult == ErrorSharingViolation
            || ex.HResult == ErrorLockViolation
            || ex.HResult == ErrorAccessDenied;
    }
}
