using System.Collections.Frozen;
using System.Text;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Primitives;
using Microsoft.Net.Http.Headers;
using MiniIdentity.Server.Options;
using MiniIdentity.Server.Tokens;

namespace MiniIdentity.Server.Endpoints;

public static partial class TokenEndpoint
{
    private const int MaximumBodyBytes = 8 * 1_024;
    private const string FormContentType = "application/x-www-form-urlencoded";
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private static readonly FrozenSet<string> RequiredParameters = new[]
    {
        "grant_type", "client_id", "code", "redirect_uri", "code_verifier",
    }.ToFrozenSet(StringComparer.Ordinal);

    public static RouteHandlerBuilder MapTokenEndpoint(this IEndpointRouteBuilder endpoints) =>
        endpoints.MapPost("/token", HandleAsync)
            .DisableAntiforgery();

    private static async Task<IResult> HandleAsync(
        HttpContext context,
        TokenRedemptionService redemptionService,
        Microsoft.Extensions.Options.IOptions<ClientOptions> clientOptions,
        ILoggerFactory loggerFactory,
        CancellationToken cancellationToken)
    {
        SetNoStoreHeaders(context.Response);

        if (context.Request.Headers.ContainsKey(HeaderNames.Authorization))
        {
            return Error("invalid_client");
        }

        Dictionary<string, StringValues>? form;
        try
        {
            form = await ReadFormAsync(context.Request, cancellationToken);
        }
        catch (BadHttpRequestException)
        {
            return Error("invalid_request");
        }
        catch (IOException) when (!context.RequestAborted.IsCancellationRequested)
        {
            return Error("invalid_request");
        }

        if (form is null)
        {
            return Error("invalid_request");
        }

        if (form.ContainsKey("client_secret"))
        {
            return Error("invalid_client");
        }

        if (form.Keys.Any(parameter => !RequiredParameters.Contains(parameter))
            || RequiredParameters.Any(parameter => !TryGetSingleNonEmpty(form, parameter, out _)))
        {
            return Error("invalid_request");
        }

        var grantType = form["grant_type"][0]!;
        if (!string.Equals(grantType, "authorization_code", StringComparison.Ordinal))
        {
            return Error("unsupported_grant_type");
        }

        var clientId = form["client_id"][0]!;
        if (!string.Equals(clientId, clientOptions.Value.Id, StringComparison.Ordinal))
        {
            return Error("invalid_client");
        }

        var code = form["code"][0]!;
        var redirectUri = form["redirect_uri"][0]!;
        var verifier = form["code_verifier"][0]!;
        if (!Uri.TryCreate(redirectUri, UriKind.Absolute, out _))
        {
            return Error("invalid_request");
        }

        if (!AuthorizationCodePattern().IsMatch(code) || !CodeVerifierPattern().IsMatch(verifier))
        {
            return Error("invalid_grant");
        }

        try
        {
            var result = await redemptionService.RedeemAsync(
                new TokenRedemptionRequest(clientId, code, redirectUri, verifier),
                cancellationToken);
            if (!result.IsSuccess)
            {
                return Error("invalid_grant");
            }

            return Results.Json(new TokenSuccessResponse(
                result.Tokens!.AccessToken,
                "Bearer",
                JwtTokenIssuer.TokenLifetimeSeconds,
                result.Tokens.IdToken,
                result.Scope!));
        }
        catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            LogTokenRedemptionFailure(
                loggerFactory.CreateLogger("MiniIdentity.TokenEndpoint"),
                exception);
            return Error("temporarily_unavailable", StatusCodes.Status503ServiceUnavailable);
        }
    }

    private static async Task<Dictionary<string, StringValues>?> ReadFormAsync(
        HttpRequest request,
        CancellationToken cancellationToken)
    {
        if (request.ContentLength is > MaximumBodyBytes
            || !MediaTypeHeaderValue.TryParse(request.ContentType, out var contentType)
            || !string.Equals(contentType.MediaType.Value, FormContentType, StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var charset = HeaderUtilities.RemoveQuotes(contentType.Charset).Value;
        if (!string.IsNullOrEmpty(charset)
            && !string.Equals(charset, "utf-8", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var buffer = new byte[MaximumBodyBytes + 1];
        var bytesRead = 0;
        while (bytesRead < buffer.Length)
        {
            var count = await request.Body.ReadAsync(buffer.AsMemory(bytesRead), cancellationToken);
            if (count == 0)
            {
                break;
            }

            bytesRead += count;
        }

        if (bytesRead == 0 || bytesRead > MaximumBodyBytes)
        {
            return null;
        }

        string body;
        try
        {
            body = StrictUtf8.GetString(buffer, 0, bytesRead);
        }
        catch (DecoderFallbackException)
        {
            return null;
        }

        if (!HasValidPercentEncoding(body)
            || body.Split('&').Any(segment => segment.Length == 0 || !segment.Contains('=', StringComparison.Ordinal)))
        {
            return null;
        }

        var form = QueryHelpers.ParseQuery($"?{body}");
        return form.Any(pair => pair.Key.Length == 0
                                || pair.Key.Contains('\uFFFD', StringComparison.Ordinal)
                                || pair.Key.Any(char.IsControl)
                                || pair.Value.Any(value => value is null
                                                           || value.Contains('\uFFFD', StringComparison.Ordinal)
                                                           || value.Any(char.IsControl)))
            ? null
            : form;
    }

    private static bool TryGetSingleNonEmpty(
        Dictionary<string, StringValues> form,
        string parameter,
        out string value)
    {
        value = string.Empty;
        if (!form.TryGetValue(parameter, out var values) || values.Count != 1 || string.IsNullOrEmpty(values[0]))
        {
            return false;
        }

        value = values[0]!;
        return true;
    }

    private static bool HasValidPercentEncoding(string value)
    {
        for (var index = 0; index < value.Length; index++)
        {
            if (value[index] != '%')
            {
                continue;
            }

            if (index + 2 >= value.Length
                || !Uri.IsHexDigit(value[index + 1])
                || !Uri.IsHexDigit(value[index + 2]))
            {
                return false;
            }

            index += 2;
        }

        return true;
    }

    private static IResult Error(string error, int statusCode = StatusCodes.Status400BadRequest) =>
        Results.Json(new TokenErrorResponse(error), statusCode: statusCode);

    private static void SetNoStoreHeaders(HttpResponse response)
    {
        response.Headers.CacheControl = "no-store";
        response.Headers.Pragma = "no-cache";
    }

    [GeneratedRegex("^[A-Za-z0-9_-]{43}$", RegexOptions.CultureInvariant)]
    private static partial Regex AuthorizationCodePattern();

    [GeneratedRegex("^[A-Za-z0-9._~-]{43,128}$", RegexOptions.CultureInvariant)]
    private static partial Regex CodeVerifierPattern();

    [LoggerMessage(
        EventId = 3_001,
        Level = LogLevel.Error,
        Message = "Token redemption failed because a required server component was unavailable.")]
    private static partial void LogTokenRedemptionFailure(ILogger logger, Exception exception);

    private sealed record TokenErrorResponse(
        [property: JsonPropertyName("error")] string Error);

    private sealed record TokenSuccessResponse(
        [property: JsonPropertyName("access_token")] string AccessToken,
        [property: JsonPropertyName("token_type")] string TokenType,
        [property: JsonPropertyName("expires_in")] int ExpiresIn,
        [property: JsonPropertyName("id_token")] string IdToken,
        [property: JsonPropertyName("scope")] string Scope);
}
