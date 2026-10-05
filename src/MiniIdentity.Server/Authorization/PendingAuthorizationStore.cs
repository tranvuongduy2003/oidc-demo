using System.Collections.Concurrent;
using System.Security.Cryptography;
using Microsoft.AspNetCore.WebUtilities;

namespace MiniIdentity.Server.Authorization;

public sealed class PendingAuthorizationStore(TimeProvider timeProvider) : BackgroundService
{
    public const int MaximumTransactions = 1_000;
    private static readonly TimeSpan TransactionLifetime = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan CleanupInterval = TimeSpan.FromMinutes(1);
    private readonly ConcurrentDictionary<string, PendingAuthorization> _transactions = new(StringComparer.Ordinal);

    public string Create(AuthorizationRequestSnapshot request, byte[] browserTokenHash)
    {
        RemoveExpired();
        if (_transactions.Count >= MaximumTransactions)
        {
            throw new PendingAuthorizationCapacityException();
        }

        while (true)
        {
            var id = WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
            var transaction = new PendingAuthorization(
                request,
                browserTokenHash.ToArray(),
                timeProvider.GetUtcNow().Add(TransactionLifetime));
            if (_transactions.TryAdd(id, transaction))
            {
                return id;
            }
        }
    }

    public async Task<PendingAuthorizationResult> BindToSessionAsync(
        string id,
        byte[] browserTokenHash,
        Guid sessionId,
        CancellationToken cancellationToken = default)
    {
        if (!_transactions.TryGetValue(id, out var transaction))
        {
            return PendingAuthorizationResult.Failed(PendingAuthorizationStatus.NotFound);
        }

        await transaction.Gate.WaitAsync(cancellationToken);
        try
        {
            var status = Validate(transaction, browserTokenHash, sessionId, allowUnboundSession: true);
            if (status != PendingAuthorizationStatus.Ready)
            {
                return PendingAuthorizationResult.Failed(status);
            }

            transaction.SessionId ??= sessionId;
            return PendingAuthorizationResult.Ready(transaction.Request);
        }
        finally
        {
            transaction.Gate.Release();
        }
    }

    public async Task<AuthorizationCompletionResult> ApproveAsync(
        string id,
        byte[] browserTokenHash,
        Guid sessionId,
        Func<AuthorizationRequestSnapshot, CancellationToken, Task<string?>> issueCode,
        CancellationToken cancellationToken = default)
    {
        if (!_transactions.TryGetValue(id, out var transaction))
        {
            return AuthorizationCompletionResult.Failed(PendingAuthorizationStatus.NotFound);
        }

        await transaction.Gate.WaitAsync(cancellationToken);
        try
        {
            var status = Validate(transaction, browserTokenHash, sessionId, allowUnboundSession: false);
            if (status != PendingAuthorizationStatus.Ready)
            {
                return AuthorizationCompletionResult.Failed(status);
            }

            var code = await issueCode(transaction.Request, cancellationToken);
            if (code is null)
            {
                return AuthorizationCompletionResult.Failed(PendingAuthorizationStatus.SessionInvalid);
            }

            transaction.IsCompleted = true;
            return AuthorizationCompletionResult.Approved(transaction.Request, code);
        }
        finally
        {
            transaction.Gate.Release();
        }
    }

    public async Task<AuthorizationCompletionResult> DenyAsync(
        string id,
        byte[] browserTokenHash,
        Guid sessionId,
        CancellationToken cancellationToken = default)
    {
        if (!_transactions.TryGetValue(id, out var transaction))
        {
            return AuthorizationCompletionResult.Failed(PendingAuthorizationStatus.NotFound);
        }

        await transaction.Gate.WaitAsync(cancellationToken);
        try
        {
            var status = Validate(transaction, browserTokenHash, sessionId, allowUnboundSession: false);
            if (status != PendingAuthorizationStatus.Ready)
            {
                return AuthorizationCompletionResult.Failed(status);
            }

            transaction.IsCompleted = true;
            return AuthorizationCompletionResult.Denied(transaction.Request);
        }
        finally
        {
            transaction.Gate.Release();
        }
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(CleanupInterval, timeProvider);
        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken))
            {
                RemoveExpired();
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Normal host shutdown.
        }
    }

    private PendingAuthorizationStatus Validate(
        PendingAuthorization transaction,
        byte[] browserTokenHash,
        Guid sessionId,
        bool allowUnboundSession)
    {
        if (transaction.ExpiresAt <= timeProvider.GetUtcNow())
        {
            return PendingAuthorizationStatus.Expired;
        }

        if (transaction.IsCompleted)
        {
            return PendingAuthorizationStatus.Completed;
        }

        if (browserTokenHash.Length != transaction.BrowserTokenHash.Length
            || !CryptographicOperations.FixedTimeEquals(browserTokenHash, transaction.BrowserTokenHash))
        {
            return PendingAuthorizationStatus.BrowserMismatch;
        }

        if ((!allowUnboundSession || transaction.SessionId.HasValue) && transaction.SessionId != sessionId)
        {
            return PendingAuthorizationStatus.SessionMismatch;
        }

        return PendingAuthorizationStatus.Ready;
    }

    private void RemoveExpired()
    {
        var now = timeProvider.GetUtcNow();
        foreach (var item in _transactions)
        {
            if (item.Value.ExpiresAt <= now)
            {
                _transactions.TryRemove(item.Key, out _);
            }
        }
    }

    private sealed class PendingAuthorization(
        AuthorizationRequestSnapshot request,
        byte[] browserTokenHash,
        DateTimeOffset expiresAt)
    {
        public AuthorizationRequestSnapshot Request { get; } = request;
        public byte[] BrowserTokenHash { get; } = browserTokenHash;
        public DateTimeOffset ExpiresAt { get; } = expiresAt;
        public SemaphoreSlim Gate { get; } = new(1, 1);
        public Guid? SessionId { get; set; }
        public bool IsCompleted { get; set; }
    }
}

public enum PendingAuthorizationStatus
{
    Ready,
    NotFound,
    Expired,
    Completed,
    BrowserMismatch,
    SessionMismatch,
    SessionInvalid,
}

public sealed record PendingAuthorizationResult(
    PendingAuthorizationStatus Status,
    AuthorizationRequestSnapshot? Request)
{
    public static PendingAuthorizationResult Ready(AuthorizationRequestSnapshot request) =>
        new(PendingAuthorizationStatus.Ready, request);

    public static PendingAuthorizationResult Failed(PendingAuthorizationStatus status) => new(status, null);
}

public sealed record AuthorizationCompletionResult(
    PendingAuthorizationStatus Status,
    AuthorizationRequestSnapshot? Request,
    string? Code,
    bool WasDenied)
{
    public static AuthorizationCompletionResult Approved(AuthorizationRequestSnapshot request, string code) =>
        new(PendingAuthorizationStatus.Ready, request, code, false);

    public static AuthorizationCompletionResult Denied(AuthorizationRequestSnapshot request) =>
        new(PendingAuthorizationStatus.Ready, request, null, true);

    public static AuthorizationCompletionResult Failed(PendingAuthorizationStatus status) =>
        new(status, null, null, false);
}

public sealed class PendingAuthorizationCapacityException : Exception
{
    public PendingAuthorizationCapacityException()
        : base("The pending authorization store is at capacity.")
    {
    }
}
