using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using MiniIdentity.Server.Security;

namespace MiniIdentity.Server.Pages;

[ResponseCache(Location = ResponseCacheLocation.None, NoStore = true)]
public sealed class LoginModel(
    UserAuthenticationService authentication,
    LoginSessionService sessions) : PageModel
{
    private const string InvalidCredentialsMessage = "The username or password is incorrect.";

    [BindProperty]
    public LoginInput Input { get; set; } = new();

    [BindProperty(SupportsGet = true)]
    public string? ReturnUrl { get; set; }

    public string? ErrorMessage { get; private set; }

    public async Task<IActionResult> OnGetAsync(CancellationToken cancellationToken)
    {
        var currentUser = await sessions.GetCurrentUserAsync(HttpContext, cancellationToken);
        return currentUser is null ? Page() : LocalRedirect(GetSafeReturnUrl());
    }

    public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken)
    {
        if (!ModelState.IsValid)
        {
            ModelState.Clear();
            ErrorMessage = InvalidCredentialsMessage;
            return Page();
        }

        var user = await authentication.AuthenticateAsync(Input.Username, Input.Password, cancellationToken);
        if (user is null)
        {
            ModelState.Clear();
            ErrorMessage = InvalidCredentialsMessage;
            return Page();
        }

        await sessions.CreateAsync(HttpContext, user, cancellationToken);
        return LocalRedirect(GetSafeReturnUrl());
    }

    private string GetSafeReturnUrl() =>
        !string.IsNullOrWhiteSpace(ReturnUrl) && Url.IsLocalUrl(ReturnUrl) ? ReturnUrl : "/";

    public sealed class LoginInput
    {
        [Required, StringLength(64)]
        public string Username { get; set; } = string.Empty;

        [Required, StringLength(256)]
        public string Password { get; set; } = string.Empty;
    }
}
