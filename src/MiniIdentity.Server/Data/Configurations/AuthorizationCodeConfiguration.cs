using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using MiniIdentity.Server.Data.Entities;

namespace MiniIdentity.Server.Data.Configurations;

public sealed class AuthorizationCodeConfiguration : IEntityTypeConfiguration<AuthorizationCode>
{
    public void Configure(EntityTypeBuilder<AuthorizationCode> builder)
    {
        builder.ToTable("authorization_codes");
        builder.HasKey(code => code.Id);
        builder.Property(code => code.Id).HasColumnName("id").ValueGeneratedNever();
        builder.Property(code => code.CodeHash).HasColumnName("code_hash").HasMaxLength(32);
        builder.HasIndex(code => code.CodeHash).IsUnique();
        builder.Property(code => code.UserId).HasColumnName("user_id");
        builder.Property(code => code.ClientId).HasColumnName("client_id").HasMaxLength(128);
        builder.Property(code => code.RedirectUri).HasColumnName("redirect_uri").HasMaxLength(2_048);
        builder.Property(code => code.Scope).HasColumnName("scope").HasMaxLength(512);
        builder.Property(code => code.Nonce).HasColumnName("nonce").HasMaxLength(512);
        builder.Property(code => code.CodeChallenge).HasColumnName("code_challenge").HasMaxLength(43);
        builder.Property(code => code.CodeChallengeMethod).HasColumnName("code_challenge_method").HasMaxLength(8);
        builder.Property(code => code.CreatedAt).HasColumnName("created_at");
        builder.Property(code => code.ExpiresAt).HasColumnName("expires_at");
        builder.Property(code => code.UsedAt).HasColumnName("used_at");
        builder.HasIndex(code => code.ExpiresAt);
        builder.HasOne(code => code.User)
            .WithMany(user => user.AuthorizationCodes)
            .HasForeignKey(code => code.UserId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}
