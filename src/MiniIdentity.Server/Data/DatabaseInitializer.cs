using Microsoft.EntityFrameworkCore;
using MiniIdentity.Server.Data.Seeding;

namespace MiniIdentity.Server.Data;

public static class DatabaseInitializer
{
    public static async Task InitializeAsync(IServiceProvider services, CancellationToken cancellationToken = default)
    {
        await using var scope = services.CreateAsyncScope();
        var factory = scope.ServiceProvider.GetRequiredService<IDbContextFactory<IdentityDbContext>>();
        var seeder = scope.ServiceProvider.GetRequiredService<UserSeeder>();
        await using var database = await factory.CreateDbContextAsync(cancellationToken);

        await database.Database.MigrateAsync(cancellationToken);
        await seeder.SeedAsync(database, cancellationToken);
    }
}
