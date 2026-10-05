using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using MiniIdentity.Server.Authorization;
using MiniIdentity.Server.Options;
using MiniIdentity.Server.Security;

namespace MiniIdentity.Server.Pages;

[ResponseCache(Location = ResponseCacheLocation.None, NoStore = true)]
public sealed class ConsentModel(
    LoginSessionService sessions,
    BrowserFlowBindingService browserBinding,
    PendingAuthorizationStore pendingAuthorizations,
    AuthorizationCodeService authorizationCodes,
    IOptions<ClientOptions> clientOptions) : PageModel
{
    private static readonly Dictionary<string, string> ScopeDescriptions =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["openid"] = "Establish your identity and allow an ID token.",
            ["profile"] = "Include your display name in the ID token.",
            ["demo.read"] = "Permit access to the protected demo API.",
        };

    [BindProperty(SupportsGet = true, Name = "transaction")]
    public string TransactionId { get; set; } = string.Empty;

    public AuthenticatedUser? CurrentUser { get; private set; }
    public string ClientName => clientOptions.Value.Name;
    public IReadOnlyList<ConsentScope> Scopes { get; private set; } = [];
    public string? ErrorMessage { get; private set; }

    public async Task<IActionResult> OnGetAsync(CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(TransactionId))
        {
            return ShowError("The authorization transaction is missing or no longer available.");
        }

        var browserTokenHash = browserBinding.GetHash(Request);
        if (browserTokenHash is null)
        {
            return ShowError("This authorization request is not bound to this browser.");
        }

        CurrentUser = await sessions.GetCurrentUserAsync(HttpContext, cancellationToken);
        if (CurrentUser is null)
        {
            var returnUrl = Url.Page("/Consent", values: new { transaction = TransactionId })!;
            return RedirectToPage("/Login", new { returnUrl });
        }

        var pending = await pendingAuthorizations.BindToSessionAsync(
            TransactionId,
            browserTokenHash,
            CurrentUser.SessionId,
            cancellationToken);
        if (pending.Status != PendingAuthorizationStatus.Ready)
        {
            return ShowError(DescribeFailure(pending.Status));
        }

        SetScopes(pending.Request!);
        return Page();
    }

    public Task<IActionResult> OnPostApproveAsync(CancellationToken cancellationToken) =>
        CompleteAsync(approve: true, cancellationToken);

    public Task<IActionResult> OnPostDenyAsync(CancellationToken cancellationToken) =>
        CompleteAsync(approve: false, cancellationToken);

    private async Task<IActionResult> CompleteAsync(bool approve, CancellationToken cancellationToken)
    {
        var browserTokenHash = browserBinding.GetHash(Request);
        if (string.IsNullOrEmpty(TransactionId) || browserTokenHash is null)
        {
            return ShowError("This authorization request is not bound to this browser.");
        }

        CurrentUser = await sessions.GetCurrentUserAsync(HttpContext, cancellationToken);
        if (CurrentUser is null)
        {
            return ShowError("Your login session expired. No authorization code was issued.");
        }

        AuthorizationCompletionResult completion;
        if (approve)
        {
            completion = await pendingAuthorizations.ApproveAsync(
                TransactionId,
                browserTokenHash,
                CurrentUser.SessionId,
                (request, token) => authorizationCodes.IssueAsync(
                    request,
                    CurrentUser.Id,
                    CurrentUser.SessionId,
                    token),
                cancellationToken);
        }
        else
        {
            completion = await pendingAuthorizations.DenyAsync(
                TransactionId,
                browserTokenHash,
                CurrentUser.SessionId,
                cancellationToken);
        }

        if (completion.Status != PendingAuthorizationStatus.Ready)
        {
            return ShowError(DescribeFailure(completion.Status));
        }

        var request = completion.Request!;
        var parameters = completion.WasDenied
            ? new Dictionary<string, string?>
            {
                ["error"] = "access_denied",
                ["state"] = request.State,
            }
            : new Dictionary<string, string?>
            {
                ["code"] = completion.Code,
                ["state"] = request.State,
            };
        return Redirect(QueryHelpers.AddQueryString(request.RedirectUri, parameters));
    }

    private PageResult ShowError(string message)
    {
        ErrorMessage = message;
        Response.StatusCode = StatusCodes.Status400BadRequest;
        return Page();
    }

    private void SetScopes(AuthorizationRequestSnapshot request) =>
        Scopes = request.Scopes
            .Select(scope => new ConsentScope(scope, ScopeDescriptions[scope]))
            .ToArray();

    private static string DescribeFailure(PendingAuthorizationStatus status) => status switch
    {
        PendingAuthorizationStatus.Expired => "This authorization request expired. No authorization code was issued.",
        PendingAuthorizationStatus.Completed => "This authorization request has already been completed.",
        PendingAuthorizationStatus.BrowserMismatch => "This authorization request belongs to a different browser.",
        PendingAuthorizationStatus.SessionMismatch => "This authorization request belongs to a different login session.",
        PendingAuthorizationStatus.SessionInvalid => "Your login session expired. No authorization code was issued.",
        _ => "This authorization request is missing or no longer available.",
    };

    public sealed record ConsentScope(string Name, string Description);
}
