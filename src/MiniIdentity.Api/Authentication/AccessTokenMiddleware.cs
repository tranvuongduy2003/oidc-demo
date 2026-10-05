using System.Net.Http.Headers;
using Microsoft.Extensions.Options;
using MiniIdentity.Api.Options;

namespace MiniIdentity.Api.Authentication;

public sealed class AccessTokenMiddleware(
    RequestDelegate next,
    AccessTokenValidator validator,
    IOptions<AccessTokenOptions> options)
{
    private readonly string _requiredScope = options.Value.RequiredScope;

    public async Task InvokeAsync(HttpContext context)
    {
        if (context.GetEndpoint()?.Metadata.GetMetadata<RequireAccessTokenMetadata>() is null)
        {
            await next(context);
            return;
        }

        context.Response.Headers.CacheControl = "no-store";
        var credentials = ReadBearerToken(context.Request);
        if (credentials.Status != BearerCredentialStatus.Present)
        {
            if (credentials.Status == BearerCredentialStatus.Invalid)
            {
                await WriteInvalidTokenAsync(context);
            }
            else
            {
                await WriteMissingCredentialsAsync(context);
            }

            return;
        }

        var validation = await validator.ValidateAsync(credentials.Token, context.RequestAborted);
        if (validation.Status == AccessTokenValidationStatus.KeysUnavailable)
        {
            await Results.Problem(
                    statusCode: StatusCodes.Status503ServiceUnavailable,
                    title: "Signing keys are temporarily unavailable.")
                .ExecuteAsync(context);
            return;
        }

        if (validation.Status != AccessTokenValidationStatus.Valid || validation.Principal is null)
        {
            await WriteInvalidTokenAsync(context);
            return;
        }

        context.User = validation.Principal;
        if (!context.User.HasClaim("scope", _requiredScope))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            context.Response.Headers.WWWAuthenticate =
                $"Bearer error=\"insufficient_scope\", scope=\"{_requiredScope}\"";
            await context.Response.WriteAsJsonAsync(
                new { error = "insufficient_scope" },
                context.RequestAborted);
            return;
        }

        await next(context);
    }

    private static BearerCredentials ReadBearerToken(HttpRequest request)
    {
        if (!request.Headers.ContainsKey("Authorization"))
        {
            return BearerCredentials.Missing();
        }

        if (request.Headers.Authorization.Count != 1
            || !AuthenticationHeaderValue.TryParse(request.Headers.Authorization.ToString(), out var authorization))
        {
            return BearerCredentials.Invalid();
        }

        if (!string.Equals(authorization.Scheme, "Bearer", StringComparison.OrdinalIgnoreCase))
        {
            return BearerCredentials.Missing();
        }

        return string.IsNullOrEmpty(authorization.Parameter)
               || authorization.Parameter.Any(char.IsWhiteSpace)
            ? BearerCredentials.Invalid()
            : BearerCredentials.Present(authorization.Parameter);
    }

    private static Task WriteMissingCredentialsAsync(HttpContext context)
    {
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        context.Response.Headers.WWWAuthenticate = "Bearer";
        return context.Response.WriteAsJsonAsync(
            new { error = "unauthorized" },
            context.RequestAborted);
    }

    private static Task WriteInvalidTokenAsync(HttpContext context)
    {
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        context.Response.Headers.WWWAuthenticate = "Bearer error=\"invalid_token\"";
        return context.Response.WriteAsJsonAsync(
            new { error = "invalid_token" },
            context.RequestAborted);
    }

    private enum BearerCredentialStatus
    {
        Missing,
        Present,
        Invalid,
    }

    private sealed record BearerCredentials(BearerCredentialStatus Status, string Token)
    {
        public static BearerCredentials Missing() => new(BearerCredentialStatus.Missing, string.Empty);
        public static BearerCredentials Present(string token) => new(BearerCredentialStatus.Present, token);
        public static BearerCredentials Invalid() => new(BearerCredentialStatus.Invalid, string.Empty);
    }
}

public sealed class RequireAccessTokenMetadata
{
    public static RequireAccessTokenMetadata Instance { get; } = new();

    private RequireAccessTokenMetadata()
    {
    }
}
