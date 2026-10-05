# Mini Identity Server

This repository is the implementation workspace for the OAuth 2.0 and OpenID
Connect learning project described in [docs/PRD.md](docs/PRD.md).


## Projects

| Path | Responsibility |
| --- | --- |
| `src/MiniIdentity.AppHost` | Aspire composition for the four workload containers |
| `src/MiniIdentity.Server` | Razor UI, protocol endpoints, persistence, and signing |
| `src/MiniIdentity.Api` | Resource API and its independent access-token validator |
| `src/MiniIdentity.WebHost` | Static-file host for the built React application |
| `src/web` | React/TypeScript public client |

## Configure FR-01 locally

The database connection is a local secret and is intentionally absent from
committed settings. Configure it for the identity-server project:

```powershell
dotnet user-secrets set "ConnectionStrings:IdentityDatabase" "Host=localhost;Port=5432;Database=mini_identity;Username=postgres;Password=<database-password>" --project src/MiniIdentity.Server
```

The stable seeded accounts and credentials are hardcoded in `UserSeeder` for
this local learning project:

- `alice` / `Alice123!Password`
- `bob` / `Bob123!Password`

Their IDs, usernames, display names, and passwords are all defined directly in
the seeder.
At startup, the seeder runs after database migrations. It creates both users
only when the users table is empty and otherwise skips seeding entirely, so
existing password hashes are never reset. Reset the local database if you
intentionally need to reseed different passwords.

For environment-based database configuration, use
`ConnectionStrings__IdentityDatabase`.

## Run and check

```powershell
dotnet restore MiniIdentity.slnx
dotnet build MiniIdentity.slnx --no-restore

Set-Location src/web
npm install
npm run build
```

Tests, Dockerfiles, protocol features, and shared libraries are introduced with
their corresponding feature milestones.

Open the identity server over HTTPS. Its login session cookie is named
`__Host-mini-id-session`, so browsers will accept it only from a secure origin.

The local browser endpoints are:

- Identity server: `https://localhost:7443`
- React application: `https://localhost:7444`
- Resource API: `https://localhost:7445`

Because cookies are scoped to host rather than port, all `localhost` services
may receive the identity cookie in HTTP request headers. It remains HttpOnly and
cannot be read by React; use distinct hostnames when host-level cookie isolation
is required.

### Session behavior

- **Sign out of the app** clears in-memory app state and the pending transaction
  in `sessionStorage`; it does not contact the identity server.
- **End identity session** first clears app state, then opens the identity
  server's confirmation page. Only its antiforgery-protected POST deletes the
  database session and cookie.
- Issued access tokens are independent and may remain valid until their normal
  expiry.
