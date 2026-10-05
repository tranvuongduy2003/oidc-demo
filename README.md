# Mini Identity Server

A small OAuth 2.0/OpenID Connect learning project built with .NET 10, React, and PostgreSQL. It demonstrates Authorization Code Flow with PKCE, consent, signed JWTs, discovery/JWKS, and a protected API without an OIDC SDK.

## Run locally

Requires the .NET 10 SDK, Node.js/npm, and PostgreSQL.

```powershell
dotnet user-secrets set "ConnectionStrings:IdentityDatabase" "Host=localhost;Port=5432;Database=mini_identity;Username=postgres;Password=<password>" --project src/MiniIdentity.Server
dotnet build MiniIdentity.slnx

Set-Location src/web
npm install
npm run build
```

Run `MiniIdentity.Server`, `MiniIdentity.WebHost`, and `MiniIdentity.Api`, then open `https://localhost:7444`.

Demo users: `alice` / `Alice123!Password` and `bob` / `Bob123!Password`.

See [docs/FEATURES.md](docs/FEATURES.md) for supported behavior and security details.
