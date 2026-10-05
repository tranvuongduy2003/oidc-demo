using System.ComponentModel.DataAnnotations;

namespace MiniIdentity.Api.Options;

public sealed class AccessTokenOptions
{
    public const string SectionName = "AccessToken";

    [Required]
    public string Issuer { get; init; } = string.Empty;

    [Required]
    public string JwksUri { get; init; } = string.Empty;

    [Required]
    public string Audience { get; init; } = string.Empty;

    [Required]
    public string ClientId { get; init; } = string.Empty;

    [Required]
    public string RequiredScope { get; init; } = string.Empty;

    [Range(256, 65_536)]
    public int MaxTokenBytes { get; init; } = 8_192;

    [Range(0, 300)]
    public int ClockSkewSeconds { get; init; } = 30;

    [Range(30, 3_600)]
    public int JwksCacheSeconds { get; init; } = 300;

    [Range(30, 3_600)]
    public int UnknownKidRefreshCooldownSeconds { get; init; } = 30;

    [Range(1, 30)]
    public int JwksTimeoutSeconds { get; init; } = 3;
}
