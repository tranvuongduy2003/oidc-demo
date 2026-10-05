using System.Data;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using MiniIdentity.Server.Data;

namespace MiniIdentity.Server.Tokens;

public sealed class TokenRedemptionService(
    IDbContextFactory<IdentityDbContext> databaseFactory,
    JwtTokenIssuer tokenIssuer,
    TimeProvider timeProvider)
{
    public async Task<TokenRedemptionResult> RedeemAsync(
        TokenRedemptionRequest request,
        CancellationToken cancellationToken = default)
    {
        var codeHash = SHA256.HashData(Encoding.ASCII.GetBytes(request.Code));
        var computedChallenge = WebEncoders.Base64UrlEncode(
            SHA256.HashData(Encoding.ASCII.GetBytes(request.CodeVerifier)));

        await using var database = await databaseFactory.CreateDbContextAsync(cancellationToken);
        await using var transaction = await database.Database.BeginTransactionAsync(
            IsolationLevel.ReadCommitted,
            cancellationToken);

        // The row lock makes validation plus issued -> consumed one indivisible transition.
        // A racing redemption waits and then observes used_at from the winner.
        var authorizationCode = await database.AuthorizationCodes
            .FromSqlInterpolated(
                $"SELECT * FROM authorization_codes WHERE code_hash = {codeHash} FOR UPDATE")
            .SingleOrDefaultAsync(cancellationToken);
        var now = timeProvider.GetUtcNow();

        if (authorizationCode is null
            || authorizationCode.UsedAt is not null
            || authorizationCode.ExpiresAt <= now
            || !string.Equals(authorizationCode.ClientId, request.ClientId, StringComparison.Ordinal)
            || !string.Equals(authorizationCode.RedirectUri, request.RedirectUri, StringComparison.Ordinal)
            || !string.Equals(authorizationCode.CodeChallengeMethod, "S256", StringComparison.Ordinal)
            || !CryptographicOperations.FixedTimeEquals(
                Encoding.ASCII.GetBytes(authorizationCode.CodeChallenge),
                Encoding.ASCII.GetBytes(computedChallenge)))
        {
            await transaction.RollbackAsync(cancellationToken);
            return TokenRedemptionResult.InvalidGrant;
        }

        var user = await database.Users
            .AsNoTracking()
            .SingleOrDefaultAsync(candidate => candidate.Id == authorizationCode.UserId, cancellationToken)
            ?? throw new InvalidOperationException("The authorization code refers to a missing user.");

        var issuedTokens = tokenIssuer.Issue(
            user.Id,
            user.DisplayName,
            authorizationCode.Scope,
            authorizationCode.Nonce);

        authorizationCode.UsedAt = now;
        await database.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return TokenRedemptionResult.Success(issuedTokens, authorizationCode.Scope);
    }
}

public sealed record TokenRedemptionRequest(
    string ClientId,
    string Code,
    string RedirectUri,
    string CodeVerifier);

public sealed record TokenRedemptionResult(
    bool IsSuccess,
    IssuedTokens? Tokens,
    string? Scope)
{
    public static TokenRedemptionResult InvalidGrant { get; } = new(false, null, null);

    public static TokenRedemptionResult Success(IssuedTokens tokens, string scope) =>
        new(true, tokens, scope);
}
