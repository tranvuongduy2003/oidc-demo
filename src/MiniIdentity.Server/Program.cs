using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Threading.RateLimiting;
using MiniIdentity.Server.Authorization;
using MiniIdentity.Server.Data;
using MiniIdentity.Server.Data.Seeding;
using MiniIdentity.Server.Endpoints;
using MiniIdentity.Server.Options;
using MiniIdentity.Server.Security;
using MiniIdentity.Server.Tokens;

var builder = WebApplication.CreateBuilder(args);
const string browserClientCorsPolicy = "BrowserClient";

var configuredRedirectUri = builder.Configuration[$"{ClientOptions.SectionName}:RedirectUri"];
if (!Uri.TryCreate(configuredRedirectUri, UriKind.Absolute, out var clientRedirectUri))
{
    throw new InvalidOperationException("Client:RedirectUri must be an absolute URI.");
}

builder.Services
    .AddOptions<ClientOptions>()
    .Bind(builder.Configuration.GetSection(ClientOptions.SectionName))
    .ValidateDataAnnotations()
    .ValidateOnStart();
builder.Services
    .AddOptions<MiniIdentity.Server.Options.SessionOptions>()
    .Bind(builder.Configuration.GetSection(MiniIdentity.Server.Options.SessionOptions.SectionName))
    .ValidateDataAnnotations()
    .ValidateOnStart();
builder.Services
    .AddOptions<ProviderOptions>()
    .Bind(builder.Configuration.GetSection(ProviderOptions.SectionName))
    .ValidateDataAnnotations()
    .Validate(
        options => Uri.TryCreate(options.Issuer, UriKind.Absolute, out var issuer)
                   && string.Equals(issuer.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
                   && !options.Issuer.EndsWith('/'),
        "Provider:Issuer must be an absolute HTTPS URI without a trailing slash.")
    .ValidateOnStart();

var connectionString = builder.Configuration.GetConnectionString("IdentityDatabase")
    ?? throw new InvalidOperationException(
        "ConnectionStrings:IdentityDatabase is required. Configure it with user secrets or an environment variable.");

builder.Services.AddDbContextFactory<IdentityDbContext>(options =>
    options.UseNpgsql(connectionString));
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton<PasswordHashingService>();
builder.Services.AddScoped<UserSeeder>();
builder.Services.AddScoped<UserAuthenticationService>();
builder.Services.AddScoped<LoginSessionService>();
builder.Services.AddSingleton<AuthorizationRequestValidator>();
builder.Services.AddSingleton<BrowserFlowBindingService>();
builder.Services.AddSingleton<PendingAuthorizationStore>();
builder.Services.AddHostedService(provider => provider.GetRequiredService<PendingAuthorizationStore>());
builder.Services.AddScoped<AuthorizationCodeService>();
builder.Services.AddSingleton<RsaSigningKey>();
builder.Services.AddSingleton<JwtTokenIssuer>();
builder.Services.AddScoped<TokenRedemptionService>();
builder.Services.AddHostedService<ExpiredSessionCleanupService>();
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(httpContext =>
    {
        if (!HttpMethods.IsPost(httpContext.Request.Method)
            || !httpContext.Request.Path.Equals("/login", StringComparison.OrdinalIgnoreCase))
        {
            return RateLimitPartition.GetNoLimiter("not-login");
        }

        var clientAddress = httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        return RateLimitPartition.GetFixedWindowLimiter(
            clientAddress,
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 5,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0,
                AutoReplenishment = true,
            });
    });
});
builder.Services.AddRazorPages(options =>
{
    options.Conventions.ConfigureFilter(new AutoValidateAntiforgeryTokenAttribute());
});
builder.Services.AddCors(options =>
{
    options.AddPolicy(browserClientCorsPolicy, policy =>
        policy.WithOrigins(clientRedirectUri.GetLeftPart(UriPartial.Authority))
            .WithMethods(HttpMethods.Get, HttpMethods.Post)
            .WithHeaders("Accept", "Content-Type"));
});

var app = builder.Build();

// Load or create the persisted key during startup so an unusable signer fails fast.
_ = app.Services.GetRequiredService<RsaSigningKey>();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();
app.UseCors();
app.UseRateLimiter();

await DatabaseInitializer.InitializeAsync(app.Services);

app.MapRazorPages();
var browserProtocolEndpoints = app.MapGroup(string.Empty)
    .RequireCors(browserClientCorsPolicy);
browserProtocolEndpoints.MapTokenEndpoint();
browserProtocolEndpoints.MapProviderMetadataEndpoints();

app.Run();

public partial class Program;
