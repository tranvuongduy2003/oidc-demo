using Microsoft.Extensions.Options;
using MiniIdentity.Server.Options;
using MiniIdentity.Server.Tokens;

namespace MiniIdentity.Server.Endpoints;

public static class ProviderMetadataEndpoints
{
    private static readonly string[] ResponseTypes = ["code"];
    private static readonly string[] ResponseModes = ["query"];
    private static readonly string[] GrantTypes = ["authorization_code"];
    private static readonly string[] SubjectTypes = ["public"];
    private static readonly string[] SigningAlgorithms = ["RS256"];
    private static readonly string[] TokenEndpointAuthenticationMethods = ["none"];
    private static readonly string[] CodeChallengeMethods = ["S256"];
    private static readonly string[] Scopes = ["openid", "profile", "demo.read"];
    private static readonly string[] Claims = ["iss", "sub", "aud", "exp", "iat", "nonce", "name"];

    public static IEndpointRouteBuilder MapProviderMetadataEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/.well-known/openid-configuration", GetDiscoveryDocument);
        endpoints.MapGet("/jwks", (RsaSigningKey signingKey) =>
            Results.Json(new { keys = new[] { signingKey.GetPublicJsonWebKey() } }));
        return endpoints;
    }

    private static IResult GetDiscoveryDocument(IOptions<ProviderOptions> providerOptions)
    {
        var issuer = providerOptions.Value.Issuer;
        return Results.Json(new Dictionary<string, object>(StringComparer.Ordinal)
        {
            ["issuer"] = issuer,
            ["authorization_endpoint"] = $"{issuer}/authorize",
            ["token_endpoint"] = $"{issuer}/token",
            ["jwks_uri"] = $"{issuer}/jwks",
            ["response_types_supported"] = ResponseTypes,
            ["response_modes_supported"] = ResponseModes,
            ["grant_types_supported"] = GrantTypes,
            ["subject_types_supported"] = SubjectTypes,
            ["id_token_signing_alg_values_supported"] = SigningAlgorithms,
            ["token_endpoint_auth_methods_supported"] = TokenEndpointAuthenticationMethods,
            ["code_challenge_methods_supported"] = CodeChallengeMethods,
            ["scopes_supported"] = Scopes,
            ["claims_supported"] = Claims,
        });
    }
}
