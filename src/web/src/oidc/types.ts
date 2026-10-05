export type PendingTransaction = {
  state: string
  nonce: string
  verifier: string
  createdAt: number
}

export type ApplicationSession = {
  subject: string
  displayName?: string
  scopes: string[]
  expiresAt: number
  accessToken: string
  idToken: string
}

export type DiscoveryMetadata = {
  authorizationEndpoint: string
  tokenEndpoint: string
  jwksUri: string
}

export type FlowProgress =
  | 'Checking provider metadata'
  | 'Creating a protected sign-in request'
  | 'Opening the identity server'
  | 'Checking the authorization response'
  | 'Redeeming the one-time code'
  | 'Validating the ID token signature and claims'

export type CallbackResult =
  | { kind: 'none' }
  | { kind: 'success'; session: ApplicationSession }
  | { kind: 'error'; message: string }

export type VerifiedIdentity = {
  subject: string
  displayName?: string
  expiresAt: number
}
