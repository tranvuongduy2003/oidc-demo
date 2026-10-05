namespace MiniIdentity.Server.Data.Entities;

public sealed class AuthorizationCode
{
    public Guid Id { get; init; }
    public required byte[] CodeHash { get; init; }
    public Guid UserId { get; init; }
    public User User { get; set; } = null!;
    public required string ClientId { get; init; }
    public required string RedirectUri { get; init; }
    public required string Scope { get; init; }
    public required string Nonce { get; init; }
    public required string CodeChallenge { get; init; }
    public required string CodeChallengeMethod { get; init; }
    public DateTimeOffset CreatedAt { get; init; }
    public DateTimeOffset ExpiresAt { get; init; }
    public DateTimeOffset? UsedAt { get; set; }
}
