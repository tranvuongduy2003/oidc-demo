using System.ComponentModel.DataAnnotations;

namespace MiniIdentity.Server.Options;

public sealed class ProviderOptions
{
    public const string SectionName = "Provider";

    [Required, Url]
    public string Issuer { get; init; } = string.Empty;

    [Required]
    public string SigningKeyPath { get; init; } = string.Empty;
}
