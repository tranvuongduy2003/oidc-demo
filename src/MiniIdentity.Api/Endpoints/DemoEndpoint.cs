using System.Security.Claims;
using MiniIdentity.Api.Authentication;

namespace MiniIdentity.Api.Endpoints;

public static class DemoEndpoint
{
    public static RouteHandlerBuilder MapDemoEndpoint(this IEndpointRouteBuilder endpoints) =>
        endpoints.MapGet("/api/demo", Handle)
            .WithMetadata(RequireAccessTokenMetadata.Instance);

    private static IResult Handle(ClaimsPrincipal user) => Results.Json(new
    {
        message = "You accessed the protected resource.",
        subject = user.FindFirstValue("sub"),
        clientId = user.FindFirstValue("client_id"),
    });
}
