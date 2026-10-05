using System.Data;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using MiniIdentity.Server.Data;
using MiniIdentity.Server.Data.Entities;

namespace MiniIdentity.Server.Authorization;

public sealed class AuthorizationCodeService(
    IDbContextFactory<IdentityDbContext> databaseFactory,
    TimeProvider timeProvider)
{
    private const int CodeEntropyBytes = 32;
    private static readonly TimeSpan CodeLifetime = TimeSpan.FromSeconds(60);

    public async Task<string?> IssueAsync(
        AuthorizationRequestSnapshot request,
        Guid userId,
        Guid sessionId,
        CancellationToken cancellationToken = default)
    {
        await using var database = await databaseFactory.CreateDbContextAsync(cancellationToken);
        await using var transaction = await database.Database.BeginTransactionAsync(
            IsolationLevel.ReadCommitted,
            cancellationToken);

        var session = await database.LoginSessions
            .FromSqlInterpolated($"SELECT * FROM login_sessions WHERE id = {sessionId} FOR UPDATE")
            .SingleOrDefaultAsync(cancellationToken);
        var now = timeProvider.GetUtcNow();
        if (session is null || session.UserId != userId || session.ExpiresAt <= now)
        {
            await transaction.RollbackAsync(cancellationToken);
            return null;
        }

        var code = WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(CodeEntropyBytes));
        database.AuthorizationCodes.Add(new AuthorizationCode
        {
            Id = Guid.NewGuid(),
            CodeHash = SHA256.HashData(Encoding.UTF8.GetBytes(code)),
            UserId = userId,
            ClientId = request.ClientId,
            RedirectUri = request.RedirectUri,
            Scope = string.Join(' ', request.Scopes),
            Nonce = request.Nonce,
            CodeChallenge = request.CodeChallenge,
            CodeChallengeMethod = request.CodeChallengeMethod,
            CreatedAt = now,
            ExpiresAt = now.Add(CodeLifetime),
        });
        await database.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return code;
    }
}
