using System.DirectoryServices.AccountManagement;

namespace EventLogCollector;

// tracked local-account attributes
internal readonly record struct AccountSnapshot(
    string? DisplayName,
    string? Description,
    bool PasswordNeverExpires,
    bool UserCannotChangePassword,
    DateTime? AccountExpirationDate)
{
    public static AccountSnapshot From(UserPrincipal user) => new(
        user.DisplayName,
        user.Description,
        user.PasswordNeverExpires,
        user.UserCannotChangePassword,
        user.AccountExpirationDate);

    // pure diff, only changed fields
    public static Dictionary<string, string> Diff(AccountSnapshot before, AccountSnapshot after)
    {
        var diff = new Dictionary<string, string>();

        if (before.DisplayName != after.DisplayName)
            diff["DisplayName"] = $"{Describe(before.DisplayName)} -> {Describe(after.DisplayName)}";
        if (before.Description != after.Description)
            diff["Description"] = $"{Describe(before.Description)} -> {Describe(after.Description)}";
        if (before.PasswordNeverExpires != after.PasswordNeverExpires)
            diff["PasswordNeverExpires"] = $"{before.PasswordNeverExpires} -> {after.PasswordNeverExpires}";
        if (before.UserCannotChangePassword != after.UserCannotChangePassword)
            diff["UserCannotChangePassword"] = $"{before.UserCannotChangePassword} -> {after.UserCannotChangePassword}";
        if (before.AccountExpirationDate != after.AccountExpirationDate)
            diff["AccountExpirationDate"] = $"{Describe(before.AccountExpirationDate)} -> {Describe(after.AccountExpirationDate)}";

        return diff;
    }

    private static string Describe(string? value) => string.IsNullOrEmpty(value) ? "(not set)" : value;
    private static string Describe(DateTime? value) => value?.ToString("u") ?? "(not set)";
}

// per-session local account attribute memory
internal sealed class AccountAttributeTracker : IDisposable
{
    private readonly PrincipalContext _context;
    private readonly Dictionary<string, AccountSnapshot> _snapshots = new(StringComparer.OrdinalIgnoreCase);

    public AccountAttributeTracker()
    {
        _context = new PrincipalContext(ContextType.Machine);
    }

    // best-effort snapshot of every existing account
    public void SeedAll()
    {
        try
        {
            using var searcher = new PrincipalSearcher(new UserPrincipal(_context));
            foreach (var result in searcher.FindAll())
            {
                if (result is UserPrincipal user && user.SamAccountName is string name)
                    _snapshots[name] = AccountSnapshot.From(user);
            }
        }
        catch
        {
            // lazily seeded later
        }
    }

    // diffs current state against last-known snapshot
    public bool TryObserve(string accountName, out Dictionary<string, string> changedFields)
    {
        changedFields = new Dictionary<string, string>();

        UserPrincipal? user;
        try
        {
            user = UserPrincipal.FindByIdentity(_context, IdentityType.SamAccountName, accountName);
        }
        catch
        {
            return false;
        }

        if (user is null)
            return false;

        var current = AccountSnapshot.From(user);
        if (_snapshots.TryGetValue(accountName, out var previous))
            changedFields = AccountSnapshot.Diff(previous, current);

        _snapshots[accountName] = current;
        return changedFields.Count > 0;
    }

    public void Dispose() => _context.Dispose();
}
