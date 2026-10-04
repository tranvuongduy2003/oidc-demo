using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using MiniIdentity.Server.Data.Entities;

namespace MiniIdentity.Server.Data.Configurations;

public sealed class UserConfiguration : IEntityTypeConfiguration<User>
{
    public void Configure(EntityTypeBuilder<User> builder)
    {
        builder.ToTable("users");
        builder.HasKey(user => user.Id);
        builder.Property(user => user.Id).HasColumnName("id").ValueGeneratedNever();
        builder.Property(user => user.Username).HasColumnName("username").HasMaxLength(64);
        builder.HasIndex(user => user.Username).IsUnique();
        builder.Property(user => user.DisplayName).HasColumnName("display_name").HasMaxLength(128);
        builder.Property(user => user.PasswordHash).HasColumnName("password_hash");
        builder.Property(user => user.PasswordSalt).HasColumnName("password_salt");
        builder.Property(user => user.PasswordAlgorithm).HasColumnName("password_algorithm").HasMaxLength(32);
        builder.Property(user => user.PasswordIterations).HasColumnName("password_iterations");
        builder.Property(user => user.CreatedAt).HasColumnName("created_at");
    }
}
