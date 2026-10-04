using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Threading.RateLimiting;
using MiniIdentity.Server.Data;
using MiniIdentity.Server.Data.Seeding;
using MiniIdentity.Server.Options;
using MiniIdentity.Server.Security;

var builder = WebApplication.CreateBuilder(args);

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

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();
app.UseRateLimiter();

await DatabaseInitializer.InitializeAsync(app.Services);

app.MapRazorPages();

app.Run();

public partial class Program;
