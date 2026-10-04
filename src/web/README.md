# Mini Identity React client

This Vite/React application is the public client described by the project PRD.
It will own PKCE generation, transaction state, callback handling, ID-token
validation through Web Crypto, and calls to the resource API.

The static host remains deliberately separate in `../MiniIdentity.WebHost`.
Running `npm run build` writes the production assets into that host's
`wwwroot` directory.

```powershell
npm install
npm run lint
npm run build
```

Authentication tokens must remain in memory. Only the short-lived pending
authorization transaction belongs in `sessionStorage`.
