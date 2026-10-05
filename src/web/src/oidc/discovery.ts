import { oidcConfig } from './config'
import { isRecord } from './guards'
import type { DiscoveryMetadata } from './types'

export async function loadTrustedMetadata(): Promise<DiscoveryMetadata> {
  const response = await fetch(`${oidcConfig.issuer}/.well-known/openid-configuration`, {
    credentials: 'omit',
    cache: 'no-store',
    headers: { Accept: 'application/json' },
    referrerPolicy: 'no-referrer',
  })
  if (!response.ok) {
    throw new Error('The identity provider metadata could not be loaded.')
  }

  const document: unknown = await response.json()
  if (!isRecord(document)) {
    throw new Error('The identity provider returned malformed metadata.')
  }

  const trustedValues = {
    issuer: oidcConfig.issuer,
    authorization_endpoint: oidcConfig.authorizationEndpoint,
    token_endpoint: oidcConfig.tokenEndpoint,
    jwks_uri: oidcConfig.jwksUri,
  }
  for (const [name, expected] of Object.entries(trustedValues)) {
    if (document[name] !== expected) {
      throw new Error(`The identity provider metadata contains an untrusted ${name}.`)
    }
  }

  return {
    authorizationEndpoint: trustedValues.authorization_endpoint,
    tokenEndpoint: trustedValues.token_endpoint,
    jwksUri: trustedValues.jwks_uri,
  }
}
