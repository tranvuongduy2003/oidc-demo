using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace MiniIdentity.Server.Data.Migrations;

[DbContext(typeof(IdentityDbContext))]
[Migration("20261004000000_InitialIdentity")]
public partial class InitialIdentity : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.CreateTable(
            name: "users",
            columns: table => new
            {
                id = table.Column<Guid>(type: "uuid", nullable: false),
                username = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                display_name = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                password_hash = table.Column<byte[]>(type: "bytea", nullable: false),
                password_salt = table.Column<byte[]>(type: "bytea", nullable: false),
                password_algorithm = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                password_iterations = table.Column<int>(type: "integer", nullable: false),
                created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
            },
            constraints: table => table.PrimaryKey("PK_users", x => x.id));

        migrationBuilder.CreateTable(
            name: "login_sessions",
            columns: table => new
            {
                id = table.Column<Guid>(type: "uuid", nullable: false),
                session_token_hash = table.Column<byte[]>(type: "bytea", maxLength: 32, nullable: false),
                user_id = table.Column<Guid>(type: "uuid", nullable: false),
                created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                expires_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_login_sessions", x => x.id);
                table.ForeignKey(
                    name: "FK_login_sessions_users_user_id",
                    column: x => x.user_id,
                    principalTable: "users",
                    principalColumn: "id",
                    onDelete: ReferentialAction.Cascade);
            });

        migrationBuilder.CreateIndex("IX_login_sessions_expires_at", "login_sessions", "expires_at");
        migrationBuilder.CreateIndex("IX_login_sessions_session_token_hash", "login_sessions", "session_token_hash", unique: true);
        migrationBuilder.CreateIndex("IX_login_sessions_user_id", "login_sessions", "user_id");
        migrationBuilder.CreateIndex("IX_users_username", "users", "username", unique: true);
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropTable("login_sessions");
        migrationBuilder.DropTable("users");
    }
}
