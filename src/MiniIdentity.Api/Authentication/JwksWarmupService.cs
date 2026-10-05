namespace MiniIdentity.Api.Authentication;

public sealed partial class JwksWarmupService(
    JwksKeyProvider keyProvider,
    ILogger<JwksWarmupService> logger) : IHostedService
{
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        if (!await keyProvider.RefreshAsync(force: false, cancellationToken))
        {
            LogUnavailableAtStartup(logger);
        }
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    [LoggerMessage(
        EventId = 2,
        Level = LogLevel.Warning,
        Message = "The resource API started without a usable JWKS cache and will return 503 until refresh succeeds.")]
    private static partial void LogUnavailableAtStartup(ILogger logger);
}
