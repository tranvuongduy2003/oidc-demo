using System.ComponentModel.DataAnnotations;

namespace MiniIdentity.Server.Options;

public sealed class ClientOptions
{
    public const string SectionName = "Client";

    [Required, Url]
    public string HomeUrl { get; init; } = string.Empty;
}
