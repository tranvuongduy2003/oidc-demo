using System.ComponentModel.DataAnnotations;

namespace MiniIdentity.Server.Options;

public sealed class SessionOptions
{
    public const string SectionName = "Session";

    [Range(1, 1_440)]
    public int LifetimeMinutes { get; init; } = 30;
}
