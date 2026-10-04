using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using MiniIdentity.Server.Data;
using MiniIdentity.Server.Data.Entities;
using MiniIdentity.Server.Options;

namespace MiniIdentity.Server.Security;

public sealed class LoginSessionService(
    IDbContextFactory<IdentityDbContext> databaseFactory,
    TimeProvider timeProvider,
    IOptions<MiniIdentity.Server.Options.SessionOptions> options)
{
    public const string CookieName = "__Host-mini-id-session";
    private const int TokenEntropyBytes = 32;
    private readonly TimeSpan _lifetime = TimeSpan.FromMinutes(options.Value.LifetimeMinutes);

    public async Task<AuthenticatedUser?> GetCurrentUserAsync(
        HttpContext httpContext,
        CancellationToken cancellationToken = default)
    {
        if (!httpContext.Request.Cookies.TryGetValue(CookieName, out var token)
            || string.IsNullOrWhiteSpace(token))
        {
            return null;
        }

        var tokenHash = HashToken(token);
        var now = timeProvider.GetUtcNow();
        await using var database = await databaseFactory.CreateDbContextAsync(cancellationToken);
        var session = await database.LoginSessions
            .AsNoTracking()
            .Include(candidate => candidate.User)
            .SingleOrDefaultAsync(candidate => candidate.SessionTokenHash == tokenHash, cancellationToken);

        if (session is null)
        {
            ClearCookie(httpContext.Response);
            return null;
        }

        if (session.ExpiresAt <= now)
        {
            database.LoginSessions.Remove(session);
            await database.SaveChangesAsync(cancellationToken);
            ClearCookie(httpContext.Response);
            return null;
        }

        return new AuthenticatedUser(
            session.User.Id,
            session.User.Username,
            session.User.DisplayName,
            session.Id,
            session.ExpiresAt);
    }

    public async Task CreateAsync(
        HttpContext httpContext,
        User user,
        CancellationToken cancellationToken = default)
    {
        var token = WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(TokenEntropyBytes));
        var tokenHash = HashToken(token);
        var now = timeProvider.GetUtcNow();
        var expiresAt = now.Add(_lifetime);

        await using var database = await databaseFactory.CreateDbContextAsync(cancellationToken);
        if (httpContext.Request.Cookies.TryGetValue(CookieName, out var previousToken)
            && !string.IsNullOrWhiteSpace(previousToken))
        {
            var previousHash = HashToken(previousToken);
            var previousSession = await database.LoginSessions
                .SingleOrDefaultAsync(candidate => candidate.SessionTokenHash == previousHash, cancellationToken);
            if (previousSession is not null)
            {
                database.LoginSessions.Remove(previousSession);
            }
        }

        database.LoginSessions.Add(new LoginSession
        {
            Id = Guid.NewGuid(),
            SessionTokenHash = tokenHash,
            UserId = user.Id,
            CreatedAt = now,
            ExpiresAt = expiresAt,
        });
        await database.SaveChangesAsync(cancellationToken);

        httpContext.Response.Cookies.Append(CookieName, token, CreateCookieOptions(expiresAt));
    }

    public async Task DeleteCurrentAsync(
        HttpContext httpContext,
        CancellationToken cancellationToken = default)
    {
        if (httpContext.Request.Cookies.TryGetValue(CookieName, out var token)
            && !string.IsNullOrWhiteSpace(token))
        {
            var tokenHash = HashToken(token);
            await using var database = await databaseFactory.CreateDbContextAsync(cancellationToken);
            var session = await database.LoginSessions
                .SingleOrDefaultAsync(candidate => candidate.SessionTokenHash == tokenHash, cancellationToken);
            if (session is not null)
            {
                database.LoginSessions.Remove(session);
                await database.SaveChangesAsync(cancellationToken);
            }
        }

        ClearCookie(httpContext.Response);
    }

    public static byte[] HashToken(string token) => SHA256.HashData(Encoding.UTF8.GetBytes(token));

    private static CookieOptions CreateCookieOptions(DateTimeOffset expiresAt) => new()
    {
        Secure = true,
        HttpOnly = true,
        SameSite = SameSiteMode.Lax,
        Path = "/",
        Expires = expiresAt,
        IsEssential = true,
    };

    private static void ClearCookie(HttpResponse response) =>
        response.Cookies.Delete(CookieName, new CookieOptions
        {
            Secure = true,
            HttpOnly = true,
            SameSite = SameSiteMode.Lax,
            Path = "/",
            IsEssential = true,
        });
}

public sealed record AuthenticatedUser(
    Guid Id,
    string Username,
    string DisplayName,
    Guid SessionId,
    DateTimeOffset ExpiresAt);
