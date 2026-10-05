namespace MiniIdentity.Server.Data.Entities;

public sealed class User
{
    public Guid Id { get; init; }
    public required string Username { get; init; }
    public required string DisplayName { get; init; }
    public required byte[] PasswordHash { get; init; }
    public required byte[] PasswordSalt { get; init; }
    public required string PasswordAlgorithm { get; init; }
    public int PasswordIterations { get; init; }
    public DateTimeOffset CreatedAt { get; init; }
    public ICollection<LoginSession> LoginSessions { get; } = [];
    public ICollection<AuthorizationCode> AuthorizationCodes { get; } = [];
}
