using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using MiniIdentity.Server.Security;

namespace MiniIdentity.Server.Pages;

public sealed class ConsentModel(LoginSessionService sessions) : PageModel
{
    public AuthenticatedUser? CurrentUser { get; private set; }

    public async Task<IActionResult> OnGetAsync(CancellationToken cancellationToken)
    {
        CurrentUser = await sessions.GetCurrentUserAsync(HttpContext, cancellationToken);
        return CurrentUser is null
            ? RedirectToPage("/Login", new { returnUrl = "/authorize" })
            : Page();
    }
}
