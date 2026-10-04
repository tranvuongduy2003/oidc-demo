using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;

#nullable disable

namespace MiniIdentity.Server.Data.Migrations;

[DbContext(typeof(IdentityDbContext))]
public partial class IdentityDbContextModelSnapshot : ModelSnapshot
{
    protected override void BuildModel(ModelBuilder modelBuilder)
    {
#pragma warning disable 612, 618
        modelBuilder.HasAnnotation("ProductVersion", "10.0.0");

        modelBuilder.Entity("MiniIdentity.Server.Data.Entities.User", entity =>
        {
            entity.Property<Guid>("Id").HasColumnType("uuid").HasColumnName("id");
            entity.Property<DateTimeOffset>("CreatedAt").HasColumnType("timestamp with time zone").HasColumnName("created_at");
            entity.Property<string>("DisplayName").IsRequired().HasMaxLength(128).HasColumnType("character varying(128)").HasColumnName("display_name");
            entity.Property<string>("PasswordAlgorithm").IsRequired().HasMaxLength(32).HasColumnType("character varying(32)").HasColumnName("password_algorithm");
            entity.Property<byte[]>("PasswordHash").IsRequired().HasColumnType("bytea").HasColumnName("password_hash");
            entity.Property<int>("PasswordIterations").HasColumnType("integer").HasColumnName("password_iterations");
            entity.Property<byte[]>("PasswordSalt").IsRequired().HasColumnType("bytea").HasColumnName("password_salt");
            entity.Property<string>("Username").IsRequired().HasMaxLength(64).HasColumnType("character varying(64)").HasColumnName("username");
            entity.HasKey("Id");
            entity.HasIndex("Username").IsUnique();
            entity.ToTable("users");
        });

        modelBuilder.Entity("MiniIdentity.Server.Data.Entities.LoginSession", entity =>
        {
            entity.Property<Guid>("Id").HasColumnType("uuid").HasColumnName("id");
            entity.Property<DateTimeOffset>("CreatedAt").HasColumnType("timestamp with time zone").HasColumnName("created_at");
            entity.Property<DateTimeOffset>("ExpiresAt").HasColumnType("timestamp with time zone").HasColumnName("expires_at");
            entity.Property<byte[]>("SessionTokenHash").IsRequired().HasMaxLength(32).HasColumnType("bytea").HasColumnName("session_token_hash");
            entity.Property<Guid>("UserId").HasColumnType("uuid").HasColumnName("user_id");
            entity.HasKey("Id");
            entity.HasIndex("ExpiresAt");
            entity.HasIndex("SessionTokenHash").IsUnique();
            entity.HasIndex("UserId");
            entity.ToTable("login_sessions");
        });

        modelBuilder.Entity("MiniIdentity.Server.Data.Entities.LoginSession", entity =>
        {
            entity.HasOne("MiniIdentity.Server.Data.Entities.User", "User")
                .WithMany("LoginSessions")
                .HasForeignKey("UserId")
                .OnDelete(DeleteBehavior.Cascade)
                .IsRequired();
            entity.Navigation("User");
        });

        modelBuilder.Entity("MiniIdentity.Server.Data.Entities.User", entity => entity.Navigation("LoginSessions"));
#pragma warning restore 612, 618
    }
}
