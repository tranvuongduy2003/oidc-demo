using MiniIdentity.Api.Authentication;
using MiniIdentity.Api.Endpoints;
using MiniIdentity.Api.Options;

var builder = WebApplication.CreateBuilder(args);
const string browserClientCorsPolicy = "BrowserClient";

builder.Services
    .AddOptions<AccessTokenOptions>()
    .Bind(builder.Configuration.GetSection(AccessTokenOptions.SectionName))
    .ValidateDataAnnotations()
    .Validate(
        options => Uri.TryCreate(options.Issuer, UriKind.Absolute, out var issuer)
                   && string.Equals(issuer.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
                   && !options.Issuer.EndsWith('/'),
        "AccessToken:Issuer must be an absolute HTTPS URI without a trailing slash.")
    .Validate(
        options => Uri.TryCreate(options.JwksUri, UriKind.Absolute, out var jwksUri)
                   && (string.Equals(jwksUri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)
                       || string.Equals(jwksUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)),
        "AccessToken:JwksUri must be an absolute HTTP or HTTPS URI.")
    .Validate(
        options => options.Audience == "mini-api"
                   && options.ClientId == "mini-spa"
                   && options.RequiredScope == "demo.read",
        "The MVP requires audience mini-api, client mini-spa, and scope demo.read.")
    .ValidateOnStart();

var browserOrigin = builder.Configuration["BrowserClientOrigin"]
    ?? throw new InvalidOperationException("BrowserClientOrigin is required.");
if (!Uri.TryCreate(browserOrigin, UriKind.Absolute, out var parsedBrowserOrigin)
    || !(string.Equals(parsedBrowserOrigin.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)
         || string.Equals(parsedBrowserOrigin.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
    || parsedBrowserOrigin.AbsolutePath != "/"
    || !string.IsNullOrEmpty(parsedBrowserOrigin.Query)
    || !string.IsNullOrEmpty(parsedBrowserOrigin.Fragment))
{
    throw new InvalidOperationException("BrowserClientOrigin must be an absolute origin without a path, query, or fragment.");
}

builder.Services.AddHttpClient(JwksKeyProvider.HttpClientName, client =>
{
    client.MaxResponseContentBufferSize = JwksKeyProvider.MaximumJwksDocumentBytes;
});
builder.Services.AddSingleton<TimeProvider>(TimeProvider.System);
builder.Services.AddSingleton<JwksKeyProvider>();
builder.Services.AddSingleton<AccessTokenValidator>();
builder.Services.AddHostedService<JwksWarmupService>();
builder.Services.AddCors(options =>
{
    options.AddPolicy(browserClientCorsPolicy, policy =>
        policy.WithOrigins(parsedBrowserOrigin.GetLeftPart(UriPartial.Authority))
            .WithMethods(HttpMethods.Get)
            .WithHeaders("Accept", "Authorization"));
});

var app = builder.Build();

app.UseHttpsRedirection();
app.UseRouting();
app.UseCors();
app.UseMiddleware<AccessTokenMiddleware>();

app.MapDemoEndpoint().RequireCors(browserClientCorsPolicy);
app.Run();

public partial class Program;
