import { oidcConfig } from './config'
import { isNonemptyString, isNumericDate, isRecord } from './guards'
import { loadVerificationKey } from './signingKeys'
import type { VerifiedIdentity } from './types'
import { decodeBase64Url, decodeJsonSegment, signingInput } from './values'

export async function validateIdToken(
  token: string,
  expectedNonce: string,
  jwksUri: string,
): Promise<VerifiedIdentity> {
  if (token.length > 32 * 1024) {
    throw new Error('The ID token is too large.')
  }

  const segments = token.split('.')
  if (segments.length !== 3 || segments.some((segment) => segment.length === 0)) {
    throw new Error('The ID token is not a compact three-part JWT.')
  }

  const header = decodeJsonSegment(segments[0])
  const claims = decodeJsonSegment(segments[1])
  const signature = decodeBase64Url(segments[2])
  if (!isRecord(header) || !isRecord(claims)) {
    throw new Error('The ID token contains malformed JSON.')
  }

  if (header.alg !== 'RS256' || header.typ !== 'JWT' || !isNonemptyString(header.kid)) {
    throw new Error('The ID token uses an unsupported header.')
  }

  const verificationKey = await loadVerificationKey(jwksUri, header.kid)
  const signatureValid = await crypto.subtle.verify(
    { name: 'RSASSA-PKCS1-v1_5' },
    verificationKey,
    signature,
    signingInput(segments[0], segments[1]),
  )
  if (!signatureValid) {
    throw new Error('The ID token signature is invalid.')
  }

  const now = Math.floor(Date.now() / 1000)
  if (
    claims.iss !== oidcConfig.issuer ||
    claims.aud !== oidcConfig.clientId ||
    !isNonemptyString(claims.sub) ||
    claims.nonce !== expectedNonce ||
    !isNumericDate(claims.iat) ||
    !isNumericDate(claims.exp) ||
    claims.iat > now + 60 ||
    claims.exp <= now ||
    claims.exp <= claims.iat ||
    (claims.name !== undefined && !isNonemptyString(claims.name))
  ) {
    throw new Error('The ID token claims are invalid.')
  }

  return {
    subject: claims.sub,
    ...(typeof claims.name === 'string' ? { displayName: claims.name } : {}),
    expiresAt: claims.exp * 1000,
  }
}
