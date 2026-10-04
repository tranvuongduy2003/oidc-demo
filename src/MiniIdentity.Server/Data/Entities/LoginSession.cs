namespace MiniIdentity.Server.Data.Entities;

public sealed class LoginSession
{
    public Guid Id { get; init; }
    public required byte[] SessionTokenHash { get; init; }
    public Guid UserId { get; init; }
    public User User { get; set; } = null!;
    public DateTimeOffset CreatedAt { get; init; }
    public DateTimeOffset ExpiresAt { get; init; }
}
