using Microsoft.EntityFrameworkCore;
using MiniIdentity.Server.Data.Entities;

namespace MiniIdentity.Server.Data;

public sealed class IdentityDbContext(DbContextOptions<IdentityDbContext> options) : DbContext(options)
{
    public DbSet<User> Users => Set<User>();
    public DbSet<LoginSession> LoginSessions => Set<LoginSession>();
    public DbSet<AuthorizationCode> AuthorizationCodes => Set<AuthorizationCode>();

    protected override void OnModelCreating(ModelBuilder modelBuilder) =>
        modelBuilder.ApplyConfigurationsFromAssembly(typeof(IdentityDbContext).Assembly);
}
