using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace MiniIdentity.Server.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddAuthorizationCodes : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "authorization_codes",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    code_hash = table.Column<byte[]>(type: "bytea", maxLength: 32, nullable: false),
                    user_id = table.Column<Guid>(type: "uuid", nullable: false),
                    client_id = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    redirect_uri = table.Column<string>(type: "character varying(2048)", maxLength: 2048, nullable: false),
                    scope = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: false),
                    nonce = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: false),
                    code_challenge = table.Column<string>(type: "character varying(43)", maxLength: 43, nullable: false),
                    code_challenge_method = table.Column<string>(type: "character varying(8)", maxLength: 8, nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    expires_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    used_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_authorization_codes", x => x.id);
                    table.ForeignKey(
                        name: "FK_authorization_codes_users_user_id",
                        column: x => x.user_id,
                        principalTable: "users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_authorization_codes_code_hash",
                table: "authorization_codes",
                column: "code_hash",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_authorization_codes_expires_at",
                table: "authorization_codes",
                column: "expires_at");

            migrationBuilder.CreateIndex(
                name: "IX_authorization_codes_user_id",
                table: "authorization_codes",
                column: "user_id");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "authorization_codes");
        }
    }
}
