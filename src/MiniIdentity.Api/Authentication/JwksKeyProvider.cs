using System.Collections.Frozen;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using MiniIdentity.Api.Options;

namespace MiniIdentity.Api.Authentication;

public sealed partial class JwksKeyProvider(
    IHttpClientFactory httpClientFactory,
    IOptions<AccessTokenOptions> options,
    TimeProvider timeProvider,
    ILogger<JwksKeyProvider> logger) : IDisposable
{
    public const string HttpClientName = "IdentityServerJwks";
    public const int MaximumJwksDocumentBytes = 64 * 1024;

    private readonly AccessTokenOptions _options = options.Value;
    private readonly SemaphoreSlim _refreshLock = new(1, 1);
    private KeySnapshot _snapshot = KeySnapshot.Empty;
    private long _lastRefreshAttemptUtcTicks;

    public async Task<KeyLookupResult> GetKeyAsync(string keyId, CancellationToken cancellationToken)
    {
        var now = timeProvider.GetUtcNow();
        var snapshot = Volatile.Read(ref _snapshot);
        if (snapshot.ExpiresAt > now && snapshot.Keys.TryGetValue(keyId, out var currentKey))
        {
            return KeyLookupResult.Found(currentKey);
        }

        var cacheWasUsable = snapshot.ExpiresAt > now;
        var forceUnknownKeyRefresh = cacheWasUsable
            && now.UtcTicks - Volatile.Read(ref _lastRefreshAttemptUtcTicks)
            >= TimeSpan.FromSeconds(_options.UnknownKidRefreshCooldownSeconds).Ticks;

        if (!cacheWasUsable || forceUnknownKeyRefresh)
        {
            var refreshed = await RefreshAsync(forceUnknownKeyRefresh, cancellationToken);
            snapshot = Volatile.Read(ref _snapshot);
            if (snapshot.ExpiresAt > timeProvider.GetUtcNow()
                && snapshot.Keys.TryGetValue(keyId, out var refreshedKey))
            {
                return KeyLookupResult.Found(refreshedKey);
            }

            if (!refreshed && !cacheWasUsable)
            {
                return KeyLookupResult.Unavailable();
            }
        }

        return KeyLookupResult.Unknown();
    }

    public async Task<bool> RefreshAsync(bool force, CancellationToken cancellationToken)
    {
        await _refreshLock.WaitAsync(cancellationToken);
        try
        {
            var now = timeProvider.GetUtcNow();
            var current = Volatile.Read(ref _snapshot);
            if (!force && current.ExpiresAt > now)
            {
                return true;
            }

            var lastAttemptUtcTicks = Volatile.Read(ref _lastRefreshAttemptUtcTicks);
            if (lastAttemptUtcTicks != 0
                && now.UtcTicks - lastAttemptUtcTicks
                < TimeSpan.FromSeconds(_options.UnknownKidRefreshCooldownSeconds).Ticks)
            {
                return current.ExpiresAt > now;
            }

            Volatile.Write(ref _lastRefreshAttemptUtcTicks, now.UtcTicks);
            try
            {
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                timeout.CancelAfter(TimeSpan.FromSeconds(_options.JwksTimeoutSeconds));
                using var request = new HttpRequestMessage(HttpMethod.Get, _options.JwksUri);
                request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                using var response = await httpClientFactory.CreateClient(HttpClientName)
                    .SendAsync(request, HttpCompletionOption.ResponseContentRead, timeout.Token);
                response.EnsureSuccessStatusCode();

                var content = await response.Content.ReadAsByteArrayAsync(timeout.Token);
                var keys = ParseKeys(content);
                if (keys.Count == 0)
                {
                    throw new JsonException("The JWKS contains no usable RS256 signing keys.");
                }

                Volatile.Write(
                    ref _snapshot,
                    new KeySnapshot(keys.ToFrozenDictionary(StringComparer.Ordinal),
                        now.AddSeconds(_options.JwksCacheSeconds)));
                return true;
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                LogRefreshFailure(logger, null);
                return false;
            }
            catch (Exception exception) when (exception is HttpRequestException
                                               or JsonException
                                               or ArgumentException)
            {
                LogRefreshFailure(logger, exception);
                return false;
            }
        }
        finally
        {
            _refreshLock.Release();
        }
    }

    public void Dispose() => _refreshLock.Dispose();

    [LoggerMessage(
        EventId = 1,
        Level = LogLevel.Warning,
        Message = "Could not refresh signing keys from the configured JWKS URI.")]
    private static partial void LogRefreshFailure(ILogger logger, Exception? exception);

    private static Dictionary<string, RsaPublicKey> ParseKeys(ReadOnlyMemory<byte> utf8Json)
    {
        using var document = JsonDocument.Parse(utf8Json, new JsonDocumentOptions
        {
            AllowTrailingCommas = false,
            CommentHandling = JsonCommentHandling.Disallow,
            MaxDepth = 8,
        });
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object
            || HasDuplicateProperties(root)
            || !root.TryGetProperty("keys", out var keysElement)
            || keysElement.ValueKind != JsonValueKind.Array)
        {
            throw new JsonException("The JWKS document is malformed.");
        }

        var keys = new Dictionary<string, RsaPublicKey>(StringComparer.Ordinal);
        foreach (var element in keysElement.EnumerateArray())
        {
            if (element.ValueKind != JsonValueKind.Object || HasDuplicateProperties(element))
            {
                continue;
            }

            if (!TryGetString(element, "kty", out var keyType)
                || keyType != "RSA"
                || !TryGetString(element, "use", out var use)
                || use != "sig"
                || !TryGetString(element, "alg", out var algorithm)
                || algorithm != "RS256"
                || !TryGetString(element, "kid", out var keyId)
                || string.IsNullOrWhiteSpace(keyId)
                || !TryGetString(element, "n", out var modulus)
                || !TryGetString(element, "e", out var exponent)
                || !TryDecodeBase64Url(modulus, out var modulusBytes)
                || !TryDecodeBase64Url(exponent, out var exponentBytes)
                || modulusBytes.Length < 256
                || exponentBytes.Length == 0)
            {
                continue;
            }

            if (!keys.TryAdd(keyId, new RsaPublicKey(modulusBytes, exponentBytes)))
            {
                throw new JsonException("The JWKS contains duplicate key identifiers.");
            }
        }

        return keys;
    }

    private static bool TryGetString(JsonElement element, string name, out string value)
    {
        value = string.Empty;
        return element.TryGetProperty(name, out var property)
               && property.ValueKind == JsonValueKind.String
               && (value = property.GetString()!) is not null;
    }

    private static bool TryDecodeBase64Url(string value, out byte[] decoded)
    {
        decoded = [];
        if (string.IsNullOrEmpty(value) || value.Contains('=') || value.Any(character =>
                !(character is >= 'A' and <= 'Z'
                  or >= 'a' and <= 'z'
                  or >= '0' and <= '9'
                  or '-' or '_')))
        {
            return false;
        }

        try
        {
            decoded = WebEncoders.Base64UrlDecode(value);
            return decoded.Length > 0;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static bool HasDuplicateProperties(JsonElement element)
    {
        var names = new HashSet<string>(StringComparer.Ordinal);
        return element.EnumerateObject().Any(property => !names.Add(property.Name));
    }

    private sealed record KeySnapshot(
        FrozenDictionary<string, RsaPublicKey> Keys,
        DateTimeOffset ExpiresAt)
    {
        public static KeySnapshot Empty { get; } = new(
            FrozenDictionary<string, RsaPublicKey>.Empty,
            DateTimeOffset.MinValue);
    }
}

public sealed record RsaPublicKey(byte[] Modulus, byte[] Exponent)
{
    public RSAParameters ToParameters() => new()
    {
        Modulus = Modulus,
        Exponent = Exponent,
    };
}

public enum KeyLookupStatus
{
    Found,
    Unknown,
    Unavailable,
}

public sealed record KeyLookupResult(KeyLookupStatus Status, RsaPublicKey? Key)
{
    public static KeyLookupResult Found(RsaPublicKey key) => new(KeyLookupStatus.Found, key);
    public static KeyLookupResult Unknown() => new(KeyLookupStatus.Unknown, null);
    public static KeyLookupResult Unavailable() => new(KeyLookupStatus.Unavailable, null);
}
