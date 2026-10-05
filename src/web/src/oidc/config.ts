const issuer = (import.meta.env.VITE_IDENTITY_ORIGIN ?? 'https://localhost:7443').replace(
  /\/$/,
  '',
)

export const oidcConfig = Object.freeze({
  issuer,
  clientId: 'mini-spa',
  redirectUri: import.meta.env.VITE_REDIRECT_URI ?? 'https://localhost:7444/callback',
  authorizationEndpoint:
    import.meta.env.VITE_AUTHORIZATION_ENDPOINT ?? `${issuer}/authorize`,
  tokenEndpoint: import.meta.env.VITE_TOKEN_ENDPOINT ?? `${issuer}/token`,
  jwksUri: import.meta.env.VITE_JWKS_URI ?? `${issuer}/jwks`,
})

export const apiConfig = Object.freeze({
  endpoint: import.meta.env.VITE_API_ENDPOINT ?? 'https://localhost:7445/api/demo',
})

export const scopes = Object.freeze({
  withApi: 'openid profile demo.read',
  identityOnly: 'openid profile',
})
