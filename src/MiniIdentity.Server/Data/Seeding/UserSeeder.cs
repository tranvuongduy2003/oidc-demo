using Microsoft.EntityFrameworkCore;
using MiniIdentity.Server.Data;
using MiniIdentity.Server.Data.Entities;
using MiniIdentity.Server.Security;

namespace MiniIdentity.Server.Data.Seeding;

public sealed class UserSeeder(
    PasswordHashingService passwords,
    TimeProvider timeProvider)
{
    public const string AlicePassword = "Alice123!Password";
    public const string BobPassword = "Bob123!Password";

    public async Task SeedAsync(
        IdentityDbContext database,
        CancellationToken cancellationToken = default)
    {
        if (await database.Users.AnyAsync(cancellationToken))
        {
            return;
        }

        database.Users.AddRange(
            CreateUser(
                Guid.Parse("a11ce000-0000-4000-8000-000000000001"),
                "alice",
                "Alice Adams",
                AlicePassword),
            CreateUser(
                Guid.Parse("b0b00000-0000-4000-8000-000000000002"),
                "bob",
                "Bob Brown",
                BobPassword));

        await database.SaveChangesAsync(cancellationToken);
    }

    private User CreateUser(Guid id, string username, string displayName, string password)
    {
        var credential = passwords.Hash(password);
        return new User
        {
            Id = id,
            Username = username,
            DisplayName = displayName,
            PasswordHash = credential.Hash,
            PasswordSalt = credential.Salt,
            PasswordAlgorithm = PasswordHashingService.Algorithm,
            PasswordIterations = credential.Iterations,
            CreatedAt = timeProvider.GetUtcNow(),
        };
    }
}
