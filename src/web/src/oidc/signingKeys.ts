import { isNonemptyString, isRecord } from './guards'

export async function loadVerificationKey(jwksUri: string, kid: string): Promise<CryptoKey> {
  const response = await fetch(jwksUri, {
    credentials: 'omit',
    cache: 'no-store',
    headers: { Accept: 'application/json' },
    referrerPolicy: 'no-referrer',
  })
  if (!response.ok) {
    throw new Error('The trusted signing keys could not be loaded.')
  }

  const document: unknown = await response.json()
  if (!isRecord(document) || !Array.isArray(document.keys)) {
    throw new Error('The signing-key response is malformed.')
  }

  const matches = document.keys.filter(
    (candidate): candidate is JsonWebKey & { kid: string } =>
      isRecord(candidate) && candidate.kid === kid,
  )
  if (matches.length !== 1) {
    throw new Error('The ID token refers to an untrusted signing key.')
  }

  const jwk = matches[0]
  if (
    jwk.kty !== 'RSA' ||
    jwk.use !== 'sig' ||
    jwk.alg !== 'RS256' ||
    !isNonemptyString(jwk.n) ||
    !isNonemptyString(jwk.e) ||
    ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth'].some((name) => name in jwk) ||
    (jwk.key_ops !== undefined && !jwk.key_ops.includes('verify'))
  ) {
    throw new Error('The selected signing key is not trusted for RS256 verification.')
  }

  try {
    return await crypto.subtle.importKey(
      'jwk',
      jwk,
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false,
      ['verify'],
    )
  } catch {
    throw new Error('The selected signing key could not be imported.')
  }
}
