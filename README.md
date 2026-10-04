# Mini Identity Server

This repository is the implementation workspace for the OAuth 2.0 and OpenID
Connect learning project described in [docs/PRD.md](docs/PRD.md).

The current state is intentionally limited to the initial application scaffold.
Dependencies and feature folders are added only when their milestone starts.

## Projects

| Path | Responsibility |
| --- | --- |
| `src/MiniIdentity.AppHost` | Aspire composition for the four workload containers |
| `src/MiniIdentity.Server` | Razor UI, protocol endpoints, persistence, and signing |
| `src/MiniIdentity.Api` | Resource API and its independent access-token validator |
| `src/MiniIdentity.WebHost` | Static-file host for the built React application |
| `src/web` | React/TypeScript public client |

## Scaffold checks

```powershell
dotnet restore MiniIdentity.slnx
dotnet build MiniIdentity.slnx --no-restore

Set-Location src/web
npm install
npm run build
```

Tests, scripts, database support, Dockerfiles, protocol features, and shared
libraries will be introduced only when their implementation begins.
