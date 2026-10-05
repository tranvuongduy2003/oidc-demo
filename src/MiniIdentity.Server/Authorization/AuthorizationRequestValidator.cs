using System.Collections.Frozen;
using System.Collections.Immutable;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using MiniIdentity.Server.Options;

namespace MiniIdentity.Server.Authorization;

public sealed partial class AuthorizationRequestValidator(IOptions<ClientOptions> clientOptions)
{
    public const int MaximumQueryStringBytes = 8 * 1_024;
    private static readonly FrozenSet<string> RecognizedParameters = new[]
    {
        "client_id", "redirect_uri", "response_type", "response_mode", "scope", "state", "nonce",
        "code_challenge", "code_challenge_method", "prompt", "display", "max_age", "ui_locales",
        "id_token_hint", "login_hint", "acr_values", "claims", "request", "request_uri", "registration",
    }.ToFrozenSet(StringComparer.Ordinal);

    private static readonly FrozenSet<string> UnsupportedParameters = new[]
    {
        "prompt", "display", "max_age", "ui_locales", "id_token_hint", "login_hint", "acr_values",
        "claims", "request", "request_uri", "registration",
    }.ToFrozenSet(StringComparer.Ordinal);

    private static readonly FrozenSet<string> SupportedScopes = new[]
    {
        "openid", "profile", "demo.read",
    }.ToFrozenSet(StringComparer.Ordinal);

    private readonly ClientOptions _client = clientOptions.Value;

    public AuthorizationValidationResult Validate(QueryString queryString)
    {
        var rawQuery = queryString.Value ?? string.Empty;
        if (Encoding.UTF8.GetByteCount(rawQuery.TrimStart('?')) > MaximumQueryStringBytes
            || !HasValidPercentEncoding(rawQuery))
        {
            return AuthorizationValidationResult.LocalError(
                "invalid_request",
                "The authorization request is malformed or too large.");
        }

        var query = QueryHelpers.ParseQuery(rawQuery);
        var clientId = GetSingle(query, "client_id");
        var redirectUri = GetSingle(query, "redirect_uri");
        var clientAndRedirectAreTrusted = clientId == _client.Id && redirectUri == _client.RedirectUri;

        if (!clientAndRedirectAreTrusted)
        {
            return AuthorizationValidationResult.LocalError(
                "invalid_request",
                "The client or redirect URI is not registered.");
        }

        var state = GetSafeState(query);
        foreach (var parameter in RecognizedParameters)
        {
            if (query.TryGetValue(parameter, out var values) && values.Count != 1)
            {
                return AuthorizationValidationResult.CallbackError(
                    _client.RedirectUri,
                    state,
                    "invalid_request",
                    $"The '{parameter}' parameter must occur exactly once.");
            }
        }

        foreach (var parameter in UnsupportedParameters)
        {
            if (query.ContainsKey(parameter))
            {
                return AuthorizationValidationResult.CallbackError(
                    _client.RedirectUri,
                    state,
                    "invalid_request",
                    $"The '{parameter}' parameter is not supported.");
            }
        }

        if (GetSingle(query, "response_type") is not { } responseType)
        {
            return MissingParameter("response_type", state);
        }

        if (!string.Equals(responseType, "code", StringComparison.Ordinal))
        {
            return AuthorizationValidationResult.CallbackError(
                _client.RedirectUri,
                state,
                "unsupported_response_type",
                "Only the authorization code response type is supported.");
        }

        var responseMode = GetSingle(query, "response_mode");
        if (query.ContainsKey("response_mode") && !string.Equals(responseMode, "query", StringComparison.Ordinal))
        {
            return AuthorizationValidationResult.CallbackError(
                _client.RedirectUri,
                state,
                "invalid_request",
                "Only the query response mode is supported.");
        }

        var scopeValue = GetSingle(query, "scope");
        if (scopeValue is null)
        {
            return MissingParameter("scope", state);
        }

        var scopes = scopeValue
            .Split(' ', StringSplitOptions.RemoveEmptyEntries)
            .Distinct(StringComparer.Ordinal)
            .ToImmutableArray();
        if (scopes.Length == 0 || !scopes.Contains("openid", StringComparer.Ordinal)
            || scopes.Any(scope => !SupportedScopes.Contains(scope)))
        {
            return AuthorizationValidationResult.CallbackError(
                _client.RedirectUri,
                state,
                "invalid_scope",
                "The request must include openid and only supported scopes.");
        }

        if (!IsBoundedValue(state))
        {
            return MissingOrInvalidParameter("state", null);
        }

        var nonce = GetSingle(query, "nonce");
        if (!IsBoundedValue(nonce))
        {
            return MissingOrInvalidParameter("nonce", state);
        }

        var codeChallenge = GetSingle(query, "code_challenge");
        if (codeChallenge is null || !CodeChallengePattern().IsMatch(codeChallenge))
        {
            return MissingOrInvalidParameter("code_challenge", state);
        }

        var codeChallengeMethod = GetSingle(query, "code_challenge_method");
        if (!string.Equals(codeChallengeMethod, "S256", StringComparison.Ordinal))
        {
            return MissingOrInvalidParameter("code_challenge_method", state);
        }

        return AuthorizationValidationResult.Success(new AuthorizationRequestSnapshot(
            _client.Id,
            _client.RedirectUri,
            responseType,
            responseMode ?? "query",
            scopes,
            state!,
            nonce!,
            codeChallenge,
            codeChallengeMethod!));
    }

    private AuthorizationValidationResult MissingParameter(string parameter, string? state) =>
        MissingOrInvalidParameter(parameter, state);

    private AuthorizationValidationResult MissingOrInvalidParameter(string parameter, string? state) =>
        AuthorizationValidationResult.CallbackError(
            _client.RedirectUri,
            state,
            "invalid_request",
            $"The '{parameter}' parameter is missing or invalid.");

    private static string? GetSingle(Dictionary<string, StringValues> query, string name) =>
        query.TryGetValue(name, out var values) && values.Count == 1 ? values[0] : null;

    private static string? GetSafeState(Dictionary<string, StringValues> query, string? fallback = null)
    {
        var state = GetSingle(query, "state");
        return IsBoundedValue(state) ? state : fallback;
    }

    private static bool IsBoundedValue(string? value) =>
        !string.IsNullOrWhiteSpace(value) && value.Length <= 512 && !value.Any(char.IsControl);

    private static bool HasValidPercentEncoding(string value)
    {
        for (var index = 0; index < value.Length; index++)
        {
            if (value[index] != '%')
            {
                continue;
            }

            if (index + 2 >= value.Length || !Uri.IsHexDigit(value[index + 1]) || !Uri.IsHexDigit(value[index + 2]))
            {
                return false;
            }

            index += 2;
        }

        return true;
    }

    [GeneratedRegex("^[A-Za-z0-9_-]{43}$", RegexOptions.CultureInvariant)]
    private static partial Regex CodeChallengePattern();
}

public sealed record AuthorizationRequestSnapshot(
    string ClientId,
    string RedirectUri,
    string ResponseType,
    string ResponseMode,
    ImmutableArray<string> Scopes,
    string State,
    string Nonce,
    string CodeChallenge,
    string CodeChallengeMethod);

public sealed record AuthorizationValidationResult(
    bool IsValid,
    bool CanRedirect,
    AuthorizationRequestSnapshot? Request,
    string? RedirectUri,
    string? State,
    string? Error,
    string? ErrorDescription)
{
    public static AuthorizationValidationResult Success(AuthorizationRequestSnapshot request) =>
        new(true, false, request, null, null, null, null);

    public static AuthorizationValidationResult LocalError(string error, string description) =>
        new(false, false, null, null, null, error, description);

    public static AuthorizationValidationResult CallbackError(
        string redirectUri,
        string? state,
        string error,
        string description) =>
        new(false, true, null, redirectUri, state, error, description);
}
