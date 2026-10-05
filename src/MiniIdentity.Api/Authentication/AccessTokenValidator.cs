using System.Globalization;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using MiniIdentity.Api.Options;

namespace MiniIdentity.Api.Authentication;

public sealed class AccessTokenValidator(
    JwksKeyProvider keyProvider,
    IOptions<AccessTokenOptions> options,
    TimeProvider timeProvider)
{
    private const string AccessTokenType = "mini-access+jwt";
    private const string SigningAlgorithm = "RS256";
    private readonly AccessTokenOptions _options = options.Value;

    public async Task<AccessTokenValidationResult> ValidateAsync(
        string token,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(token)
            || token.Length > _options.MaxTokenBytes
            || token.Any(character => character > 0x7f))
        {
            return AccessTokenValidationResult.Invalid();
        }

        var segments = token.Split('.');
        if (segments.Length != 3
            || segments.Any(segment => !IsBase64Url(segment))
            || !TryDecodeSegment(segments[0], out var headerBytes)
            || !TryDecodeSegment(segments[1], out var payloadBytes)
            || !TryDecodeSegment(segments[2], out var signature))
        {
            return AccessTokenValidationResult.Invalid();
        }

        try
        {
            using var headerDocument = ParseJsonObject(headerBytes);
            var header = headerDocument.RootElement;
            if (!HasExactlyOneString(header, "alg", SigningAlgorithm)
                || !HasExactlyOneString(header, "typ", AccessTokenType)
                || !TryGetRequiredString(header, "kid", out var keyId)
                || keyId.Length > 512
                || header.TryGetProperty("crit", out _))
            {
                return AccessTokenValidationResult.Invalid();
            }

            var keyLookup = await keyProvider.GetKeyAsync(keyId, cancellationToken);
            if (keyLookup.Status == KeyLookupStatus.Unavailable)
            {
                return AccessTokenValidationResult.KeysUnavailable();
            }

            if (keyLookup.Status != KeyLookupStatus.Found || keyLookup.Key is null)
            {
                return AccessTokenValidationResult.Invalid();
            }

            var signingInput = Encoding.ASCII.GetBytes($"{segments[0]}.{segments[1]}");
            using var rsa = RSA.Create();
            rsa.ImportParameters(keyLookup.Key.ToParameters());
            if (!rsa.VerifyData(
                    signingInput,
                    signature,
                    HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pkcs1))
            {
                return AccessTokenValidationResult.Invalid();
            }

            using var payloadDocument = ParseJsonObject(payloadBytes);
            var payload = payloadDocument.RootElement;
            if (!HasExactlyOneString(payload, "iss", _options.Issuer)
                || !HasExactlyOneString(payload, "aud", _options.Audience)
                || !HasExactlyOneString(payload, "client_id", _options.ClientId)
                || !TryGetRequiredString(payload, "sub", out var subject)
                || !TryGetRequiredString(payload, "jti", out var tokenId)
                || !TryGetRequiredString(payload, "scope", out var scope)
                || !TryGetInt64(payload, "iat", out var issuedAt)
                || !TryGetInt64(payload, "exp", out var expiresAt)
                || !TryParseScope(scope, out var scopes)
                || !HasValidLifetime(issuedAt, expiresAt))
            {
                return AccessTokenValidationResult.Invalid();
            }

            var claims = new List<Claim>
            {
                new("iss", _options.Issuer),
                new(ClaimTypes.NameIdentifier, subject),
                new("sub", subject),
                new("aud", _options.Audience),
                new("client_id", _options.ClientId),
                new("jti", tokenId),
                new("iat", issuedAt.ToString(CultureInfo.InvariantCulture), ClaimValueTypes.Integer64),
                new("exp", expiresAt.ToString(CultureInfo.InvariantCulture), ClaimValueTypes.Integer64),
            };
            claims.AddRange(scopes.Select(value => new Claim("scope", value)));

            return AccessTokenValidationResult.Valid(
                new ClaimsPrincipal(new ClaimsIdentity(claims, authenticationType: "Bearer")));
        }
        catch (Exception exception) when (exception is JsonException
                                           or CryptographicException
                                           or FormatException
                                           or ArgumentException)
        {
            return AccessTokenValidationResult.Invalid();
        }
    }

    private bool HasValidLifetime(long issuedAt, long expiresAt)
    {
        if (issuedAt < 0 || expiresAt <= issuedAt)
        {
            return false;
        }

        var now = timeProvider.GetUtcNow().ToUnixTimeSeconds();
        var skew = _options.ClockSkewSeconds;
        return issuedAt <= now + skew && expiresAt > now - skew;
    }

    private static JsonDocument ParseJsonObject(ReadOnlyMemory<byte> utf8Json)
    {
        var document = JsonDocument.Parse(utf8Json, new JsonDocumentOptions
        {
            AllowTrailingCommas = false,
            CommentHandling = JsonCommentHandling.Disallow,
            MaxDepth = 16,
        });
        if (document.RootElement.ValueKind != JsonValueKind.Object
            || HasDuplicateProperties(document.RootElement))
        {
            document.Dispose();
            throw new JsonException("JWT segments must be JSON objects with unique member names.");
        }

        return document;
    }

    private static bool HasExactlyOneString(JsonElement element, string name, string expected) =>
        element.TryGetProperty(name, out var property)
        && property.ValueKind == JsonValueKind.String
        && string.Equals(property.GetString(), expected, StringComparison.Ordinal);

    private static bool TryGetRequiredString(JsonElement element, string name, out string value)
    {
        value = string.Empty;
        if (!element.TryGetProperty(name, out var property) || property.ValueKind != JsonValueKind.String)
        {
            return false;
        }

        value = property.GetString()!;
        return !string.IsNullOrWhiteSpace(value);
    }

    private static bool TryGetInt64(JsonElement element, string name, out long value)
    {
        value = 0;
        return element.TryGetProperty(name, out var property)
               && property.ValueKind == JsonValueKind.Number
               && property.TryGetInt64(out value);
    }

    private static bool TryParseScope(string value, out string[] scopes)
    {
        scopes = [];
        if (string.IsNullOrEmpty(value)
            || value[0] == ' '
            || value[^1] == ' '
            || value.Contains("  ", StringComparison.Ordinal)
            || value.Any(character => character != ' '
                && character != '!'
                && !(character is >= '#' and <= '[')
                && !(character is >= ']' and <= '~')))
        {
            return false;
        }

        scopes = value.Split(' ');
        return scopes.Distinct(StringComparer.Ordinal).Count() == scopes.Length;
    }

    private static bool HasDuplicateProperties(JsonElement element)
    {
        var names = new HashSet<string>(StringComparer.Ordinal);
        return element.EnumerateObject().Any(property => !names.Add(property.Name));
    }

    private static bool IsBase64Url(string value) =>
        value.Length > 0
        && !value.Contains('=')
        && value.All(character => character is >= 'A' and <= 'Z'
            or >= 'a' and <= 'z'
            or >= '0' and <= '9'
            or '-' or '_');

    private static bool TryDecodeSegment(string value, out byte[] bytes)
    {
        bytes = [];
        try
        {
            bytes = WebEncoders.Base64UrlDecode(value);
            return bytes.Length > 0;
        }
        catch (FormatException)
        {
            return false;
        }
    }
}

public enum AccessTokenValidationStatus
{
    Valid,
    Invalid,
    KeysUnavailable,
}

public sealed record AccessTokenValidationResult(
    AccessTokenValidationStatus Status,
    ClaimsPrincipal? Principal)
{
    public static AccessTokenValidationResult Valid(ClaimsPrincipal principal) =>
        new(AccessTokenValidationStatus.Valid, principal);

    public static AccessTokenValidationResult Invalid() =>
        new(AccessTokenValidationStatus.Invalid, null);

    public static AccessTokenValidationResult KeysUnavailable() =>
        new(AccessTokenValidationStatus.KeysUnavailable, null);
}
