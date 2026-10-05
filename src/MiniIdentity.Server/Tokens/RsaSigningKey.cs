using System.Security.Cryptography;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using MiniIdentity.Server.Options;

namespace MiniIdentity.Server.Tokens;

public sealed class RsaSigningKey : IDisposable
{
    private const int KeySizeBits = 3_072;
    private readonly Lock _signingLock = new();
    private readonly RSA _rsa;
    private readonly PublicJsonWebKey _publicJsonWebKey;

    public RsaSigningKey(IOptions<ProviderOptions> providerOptions, IWebHostEnvironment environment)
    {
        var configuredPath = providerOptions.Value.SigningKeyPath;
        var keyPath = Path.IsPathRooted(configuredPath)
            ? configuredPath
            : Path.GetFullPath(configuredPath, environment.ContentRootPath);

        _rsa = LoadOrCreate(keyPath);
        KeyId = WebEncoders.Base64UrlEncode(SHA256.HashData(_rsa.ExportSubjectPublicKeyInfo()));
        var parameters = _rsa.ExportParameters(includePrivateParameters: false);
        _publicJsonWebKey = new PublicJsonWebKey(
            "RSA",
            "sig",
            "RS256",
            KeyId,
            WebEncoders.Base64UrlEncode(parameters.Modulus!),
            WebEncoders.Base64UrlEncode(parameters.Exponent!));
    }

    public string KeyId { get; }

    public byte[] Sign(ReadOnlySpan<byte> data)
    {
        lock (_signingLock)
        {
            return _rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
    }

    public PublicJsonWebKey GetPublicJsonWebKey() => _publicJsonWebKey;

    public void Dispose() => _rsa.Dispose();

    private static RSA LoadOrCreate(string keyPath)
    {
        if (File.Exists(keyPath))
        {
            return Load(keyPath);
        }

        var directory = Path.GetDirectoryName(keyPath)
            ?? throw new InvalidOperationException("The signing-key path must include a directory.");
        Directory.CreateDirectory(directory);

        var temporaryPath = $"{keyPath}.{Guid.NewGuid():N}.tmp";
        try
        {
            using var generatedKey = RSA.Create(KeySizeBits);
            File.WriteAllText(temporaryPath, generatedKey.ExportPkcs8PrivateKeyPem());
            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(temporaryPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }

            File.Move(temporaryPath, keyPath, overwrite: false);
        }
        catch (IOException) when (File.Exists(keyPath))
        {
            // Another process won the create-new race. Its complete key is authoritative.
        }
        finally
        {
            if (File.Exists(temporaryPath))
            {
                File.Delete(temporaryPath);
            }
        }

        return Load(keyPath);
    }

    private static RSA Load(string keyPath)
    {
        var rsa = RSA.Create();
        try
        {
            rsa.ImportFromPem(File.ReadAllText(keyPath));
            _ = rsa.ExportParameters(includePrivateParameters: true);
            return rsa;
        }
        catch
        {
            rsa.Dispose();
            throw;
        }
    }
}

public sealed record PublicJsonWebKey(
    [property: System.Text.Json.Serialization.JsonPropertyName("kty")] string KeyType,
    [property: System.Text.Json.Serialization.JsonPropertyName("use")] string Use,
    [property: System.Text.Json.Serialization.JsonPropertyName("alg")] string Algorithm,
    [property: System.Text.Json.Serialization.JsonPropertyName("kid")] string KeyId,
    [property: System.Text.Json.Serialization.JsonPropertyName("n")] string Modulus,
    [property: System.Text.Json.Serialization.JsonPropertyName("e")] string Exponent);
