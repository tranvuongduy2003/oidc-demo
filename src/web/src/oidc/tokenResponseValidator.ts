import { isRecord } from './guards'
import { validateIdToken } from './idTokenValidator'
import type { ApplicationSession } from './types'

const allowedScopes = new Set(['openid', 'profile', 'demo.read'])

export async function validateTokenResponse(
  value: unknown,
  expectedNonce: string,
  jwksUri: string,
): Promise<ApplicationSession> {
  if (
    !isRecord(value) ||
    typeof value.access_token !== 'string' ||
    value.access_token.length === 0 ||
    typeof value.id_token !== 'string' ||
    value.id_token.length === 0 ||
    value.token_type !== 'Bearer' ||
    !Number.isSafeInteger(value.expires_in) ||
    (value.expires_in as number) <= 0 ||
    typeof value.scope !== 'string'
  ) {
    throw new Error('The token endpoint returned an invalid response.')
  }

  const grantedScopes = parseGrantedScopes(value.scope)
  const identity = await validateIdToken(value.id_token, expectedNonce, jwksUri)
  const responseExpiry = Date.now() + (value.expires_in as number) * 1000

  return {
    subject: identity.subject,
    ...(identity.displayName ? { displayName: identity.displayName } : {}),
    scopes: grantedScopes,
    expiresAt: Math.min(identity.expiresAt, responseExpiry),
    accessToken: value.access_token,
    idToken: value.id_token,
  }
}

function parseGrantedScopes(scope: string): string[] {
  const values = scope.split(' ')
  const unique = new Set(values)
  if (
    values.length === 0 ||
    values.some((value) => value.length === 0 || !allowedScopes.has(value)) ||
    unique.size !== values.length ||
    !unique.has('openid')
  ) {
    throw new Error('The token endpoint returned an invalid scope set.')
  }

  return values
}
