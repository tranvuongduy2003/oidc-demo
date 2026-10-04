using Microsoft.EntityFrameworkCore;
using MiniIdentity.Server.Data;
using MiniIdentity.Server.Data.Entities;

namespace MiniIdentity.Server.Security;

public sealed class UserAuthenticationService(
    IDbContextFactory<IdentityDbContext> databaseFactory,
    PasswordHashingService passwords)
{
    public async Task<User?> AuthenticateAsync(
        string username,
        string password,
        CancellationToken cancellationToken = default)
    {
        var normalizedUsername = username.Trim().ToLowerInvariant();
        await using var database = await databaseFactory.CreateDbContextAsync(cancellationToken);
        var user = await database.Users
            .AsNoTracking()
            .SingleOrDefaultAsync(candidate => candidate.Username == normalizedUsername, cancellationToken);

        if (user is null)
        {
            passwords.PerformDummyVerification(password);
            return null;
        }

        var credential = new UserCredential(
            user.PasswordHash,
            user.PasswordSalt,
            user.PasswordAlgorithm,
            user.PasswordIterations);

        return passwords.Verify(password, credential) ? user : null;
    }
}
