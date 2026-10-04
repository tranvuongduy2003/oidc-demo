using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using MiniIdentity.Server.Data.Entities;

namespace MiniIdentity.Server.Data.Configurations;

public sealed class LoginSessionConfiguration : IEntityTypeConfiguration<LoginSession>
{
    public void Configure(EntityTypeBuilder<LoginSession> builder)
    {
        builder.ToTable("login_sessions");
        builder.HasKey(session => session.Id);
        builder.Property(session => session.Id).HasColumnName("id").ValueGeneratedNever();
        builder.Property(session => session.SessionTokenHash).HasColumnName("session_token_hash").HasMaxLength(32);
        builder.HasIndex(session => session.SessionTokenHash).IsUnique();
        builder.Property(session => session.UserId).HasColumnName("user_id");
        builder.Property(session => session.CreatedAt).HasColumnName("created_at");
        builder.Property(session => session.ExpiresAt).HasColumnName("expires_at");
        builder.HasIndex(session => session.ExpiresAt);
        builder.HasOne(session => session.User)
            .WithMany(user => user.LoginSessions)
            .HasForeignKey(session => session.UserId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}
