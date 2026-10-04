var app = WebApplication.CreateBuilder(args).Build();

app.UseHttpsRedirection();

app.Run();
