using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.WebUtilities;

namespace MiniIdentity.Server.Authorization;

public sealed class BrowserFlowBindingService(TimeProvider timeProvider)
{
    public const string CookieName = "__Host-mini-id-flow";
    private const int TokenEntropyBytes = 32;
    private static readonly TimeSpan CookieLifetime = TimeSpan.FromMinutes(5);

    public byte[] GetOrCreateHash(HttpContext httpContext)
    {
        var token = GetValidToken(httpContext.Request);
        if (token is null)
        {
            token = WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(TokenEntropyBytes));
        }

        httpContext.Response.Cookies.Append(
            CookieName,
            token,
            CreateCookieOptions(timeProvider.GetUtcNow().Add(CookieLifetime)));
        return HashToken(token);
    }

    public byte[]? GetHash(HttpRequest request)
    {
        var token = GetValidToken(request);
        return token is null ? null : HashToken(token);
    }

    private static string? GetValidToken(HttpRequest request)
    {
        if (!request.Cookies.TryGetValue(CookieName, out var token) || string.IsNullOrEmpty(token))
        {
            return null;
        }

        try
        {
            return WebEncoders.Base64UrlDecode(token).Length == TokenEntropyBytes ? token : null;
        }
        catch (FormatException)
        {
            return null;
        }
    }

    private static byte[] HashToken(string token) => SHA256.HashData(Encoding.UTF8.GetBytes(token));

    private static CookieOptions CreateCookieOptions(DateTimeOffset expiresAt) => new()
    {
        Secure = true,
        HttpOnly = true,
        SameSite = SameSiteMode.Lax,
        Path = "/",
        Expires = expiresAt,
        IsEssential = true,
    };
}
