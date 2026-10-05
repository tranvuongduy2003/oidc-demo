using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using MiniIdentity.Server.Options;

namespace MiniIdentity.Server.Tokens;

public sealed class JwtTokenIssuer(
    RsaSigningKey signingKey,
    IOptions<ProviderOptions> providerOptions,
    TimeProvider timeProvider)
{
    public const int TokenLifetimeSeconds = 300;
    private readonly string _issuer = providerOptions.Value.Issuer;

    public IssuedTokens Issue(Guid userId, string displayName, string scope, string nonce)
    {
        var issuedAt = timeProvider.GetUtcNow().ToUnixTimeSeconds();
        var expiresAt = issuedAt + TokenLifetimeSeconds;
        var subject = userId.ToString("D");

        var idTokenClaims = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            ["iss"] = _issuer,
            ["sub"] = subject,
            ["aud"] = "mini-spa",
            ["iat"] = issuedAt,
            ["exp"] = expiresAt,
            ["nonce"] = nonce,
        };
        if (scope.Split(' ', StringSplitOptions.RemoveEmptyEntries).Contains("profile", StringComparer.Ordinal))
        {
            idTokenClaims["name"] = displayName;
        }

        var accessTokenClaims = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            ["iss"] = _issuer,
            ["sub"] = subject,
            ["aud"] = "mini-api",
            ["client_id"] = "mini-spa",
            ["scope"] = scope,
            ["iat"] = issuedAt,
            ["exp"] = expiresAt,
            ["jti"] = Guid.NewGuid().ToString("D"),
        };

        return new IssuedTokens(
            CreateToken("mini-access+jwt", accessTokenClaims),
            CreateToken("JWT", idTokenClaims),
            expiresAt);
    }

    private string CreateToken(string tokenType, Dictionary<string, object> claims)
    {
        var header = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["alg"] = "RS256",
            ["kid"] = signingKey.KeyId,
            ["typ"] = tokenType,
        };

        var encodedHeader = WebEncoders.Base64UrlEncode(JsonSerializer.SerializeToUtf8Bytes(header));
        var encodedPayload = WebEncoders.Base64UrlEncode(JsonSerializer.SerializeToUtf8Bytes(claims));
        var signingInput = $"{encodedHeader}.{encodedPayload}";
        var signature = signingKey.Sign(Encoding.ASCII.GetBytes(signingInput));
        return $"{signingInput}.{WebEncoders.Base64UrlEncode(signature)}";
    }
}

public sealed record IssuedTokens(string AccessToken, string IdToken, long ExpiresAt);
