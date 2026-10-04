using Microsoft.EntityFrameworkCore;
using MiniIdentity.Server.Data;

namespace MiniIdentity.Server.Security;

public sealed class ExpiredSessionCleanupService(
    IDbContextFactory<IdentityDbContext> databaseFactory,
    TimeProvider timeProvider,
    ILogger<ExpiredSessionCleanupService> logger) : BackgroundService
{
    private static readonly TimeSpan CleanupInterval = TimeSpan.FromMinutes(5);
    private static readonly Action<ILogger, int, Exception?> LogExpiredSessionsRemoved =
        LoggerMessage.Define<int>(
            LogLevel.Information,
            new EventId(1, "ExpiredSessionsRemoved"),
            "Removed {ExpiredSessionCount} expired login sessions.");

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(CleanupInterval, timeProvider);
        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken))
            {
                await using var database = await databaseFactory.CreateDbContextAsync(stoppingToken);
                var removed = await database.LoginSessions
                    .Where(session => session.ExpiresAt <= timeProvider.GetUtcNow())
                    .ExecuteDeleteAsync(stoppingToken);
                if (removed > 0)
                {
                    LogExpiredSessionsRemoved(logger, removed, null);
                }
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Normal host shutdown.
        }
    }
}
