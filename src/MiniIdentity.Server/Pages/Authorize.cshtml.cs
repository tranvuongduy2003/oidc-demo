using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using MiniIdentity.Server.Security;

namespace MiniIdentity.Server.Pages;

public sealed class AuthorizeModel(LoginSessionService sessions) : PageModel
{
    public async Task<IActionResult> OnGetAsync(CancellationToken cancellationToken)
    {
        var currentUser = await sessions.GetCurrentUserAsync(HttpContext, cancellationToken);
        if (currentUser is null)
        {
            var returnUrl = Request.PathBase.Add(Request.Path) + Request.QueryString;
            return RedirectToPage("/Login", new { returnUrl });
        }

        return RedirectToPage("/Consent");
    }
}
