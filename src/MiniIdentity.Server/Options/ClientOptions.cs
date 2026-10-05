using System.ComponentModel.DataAnnotations;

namespace MiniIdentity.Server.Options;

public sealed class ClientOptions
{
    public const string SectionName = "Client";

    [Required]
    public string Id { get; init; } = string.Empty;

    [Required]
    public string Name { get; init; } = string.Empty;

    [Required, Url]
    public string RedirectUri { get; init; } = string.Empty;

    [Required, Url]
    public string HomeUrl { get; init; } = string.Empty;
}
