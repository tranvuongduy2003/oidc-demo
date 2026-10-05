using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.WebUtilities;
using MiniIdentity.Server.Authorization;
using MiniIdentity.Server.Security;

namespace MiniIdentity.Server.Pages;

[ResponseCache(Location = ResponseCacheLocation.None, NoStore = true)]
public sealed class AuthorizeModel(
    AuthorizationRequestValidator validator,
    BrowserFlowBindingService browserBinding,
    PendingAuthorizationStore pendingAuthorizations,
    LoginSessionService sessions) : PageModel
{
    public string? ErrorCode { get; private set; }
    public string? ErrorDescription { get; private set; }

    public async Task<IActionResult> OnGetAsync(CancellationToken cancellationToken)
    {
        var validation = validator.Validate(Request.QueryString);
        if (!validation.IsValid)
        {
            if (validation.CanRedirect)
            {
                return Redirect(BuildErrorRedirect(validation));
            }

            return ShowLocalError(validation.Error!, validation.ErrorDescription!, StatusCodes.Status400BadRequest);
        }

        string transactionId;
        try
        {
            var browserTokenHash = browserBinding.GetOrCreateHash(HttpContext);
            transactionId = pendingAuthorizations.Create(validation.Request!, browserTokenHash);
        }
        catch (PendingAuthorizationCapacityException)
        {
            return ShowLocalError(
                "temporarily_unavailable",
                "The identity server is handling too many authorization requests. Please try again.",
                StatusCodes.Status503ServiceUnavailable);
        }

        var consentUrl = Url.Page("/Consent", values: new { transaction = transactionId })!;
        var currentUser = await sessions.GetCurrentUserAsync(HttpContext, cancellationToken);
        return currentUser is null
            ? RedirectToPage("/Login", new { returnUrl = consentUrl })
            : LocalRedirect(consentUrl);
    }

    private PageResult ShowLocalError(string error, string description, int statusCode)
    {
        ErrorCode = error;
        ErrorDescription = description;
        Response.StatusCode = statusCode;
        return Page();
    }

    private static string BuildErrorRedirect(AuthorizationValidationResult validation)
    {
        var parameters = new Dictionary<string, string?>
        {
            ["error"] = validation.Error,
            ["error_description"] = validation.ErrorDescription,
        };
        if (validation.State is not null)
        {
            parameters["state"] = validation.State;
        }

        return QueryHelpers.AddQueryString(validation.RedirectUri!, parameters);
    }
}
