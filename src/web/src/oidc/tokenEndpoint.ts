import { oidcConfig } from './config'
import { isRecord } from './guards'

export async function redeemCode(
  tokenEndpoint: string,
  code: string,
  verifier: string,
): Promise<unknown> {
  const response = await fetch(tokenEndpoint, {
    method: 'POST',
    credentials: 'omit',
    cache: 'no-store',
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: oidcConfig.clientId,
      code,
      redirect_uri: oidcConfig.redirectUri,
      code_verifier: verifier,
    }),
    referrerPolicy: 'no-referrer',
  })

  let body: unknown
  try {
    body = await response.json()
  } catch {
    throw new Error(
      response.ok
        ? 'The token response was malformed.'
        : 'The token endpoint returned an unreadable error.',
    )
  }

  if (!response.ok) {
    const error = isRecord(body) && typeof body.error === 'string' ? body.error : 'request_failed'
    throw new Error(`The identity server rejected the token request (${error}). Start a new sign-in.`)
  }

  return body
}
