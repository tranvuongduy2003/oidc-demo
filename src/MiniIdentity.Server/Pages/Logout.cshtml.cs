using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Options;
using MiniIdentity.Server.Options;
using MiniIdentity.Server.Security;

namespace MiniIdentity.Server.Pages;

[ResponseCache(Location = ResponseCacheLocation.None, NoStore = true)]
public sealed class LogoutModel(
    LoginSessionService sessions,
    IOptions<ClientOptions> clientOptions) : PageModel
{
    public AuthenticatedUser? CurrentUser { get; private set; }
    public string ApplicationHomeUrl => clientOptions.Value.HomeUrl;

    public async Task OnGetAsync(CancellationToken cancellationToken)
    {
        CurrentUser = await sessions.GetCurrentUserAsync(HttpContext, cancellationToken);
    }

    public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken)
    {
        await sessions.DeleteCurrentAsync(HttpContext, cancellationToken);
        return Redirect(ApplicationHomeUrl);
    }
}
