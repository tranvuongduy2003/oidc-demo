using System.Security.Cryptography;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;

namespace MiniIdentity.Server.Security;

public sealed class PasswordHashingService
{
    public const string Algorithm = "PBKDF2-SHA256";
    public const int Iterations = 600_000;
    private const int SaltSize = 16;
    private const int HashSize = 32;
    private readonly PasswordCredential _dummyCredential;

    public PasswordHashingService()
    {
        _dummyCredential = Hash("dummy-password-used-only-for-timing");
    }

    public PasswordCredential Hash(string password)
    {
        ArgumentException.ThrowIfNullOrEmpty(password);
        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        return new PasswordCredential(Derive(password, salt, Iterations), salt, Iterations);
    }

    public bool Verify(string password, UserCredential credential)
    {
        if (!string.Equals(credential.Algorithm, Algorithm, StringComparison.Ordinal)
            || credential.Iterations <= 0
            || credential.Salt.Length != SaltSize
            || credential.Hash.Length != HashSize)
        {
            return false;
        }

        var candidate = Derive(password, credential.Salt, credential.Iterations);
        return CryptographicOperations.FixedTimeEquals(candidate, credential.Hash);
    }

    public void PerformDummyVerification(string password)
    {
        _ = Verify(
            password,
            new UserCredential(
                _dummyCredential.Hash,
                _dummyCredential.Salt,
                Algorithm,
                _dummyCredential.Iterations));
    }

    private static byte[] Derive(string password, byte[] salt, int iterations) =>
        KeyDerivation.Pbkdf2(
            password,
            salt,
            KeyDerivationPrf.HMACSHA256,
            iterations,
            HashSize);
}

public sealed record PasswordCredential(byte[] Hash, byte[] Salt, int Iterations);

public sealed record UserCredential(byte[] Hash, byte[] Salt, string Algorithm, int Iterations);
