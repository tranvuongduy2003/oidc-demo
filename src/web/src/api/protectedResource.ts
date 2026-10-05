import { apiConfig } from '../oidc'

export type ProtectedResourceResult =
  | { kind: 'success'; message: string; details: string }
  | { kind: 'unauthorized' }
  | { kind: 'forbidden' }
  | { kind: 'error'; message: string }

export async function callProtectedResource(
  accessToken: string,
): Promise<ProtectedResourceResult> {
  try {
    const response = await fetch(apiConfig.endpoint, {
      credentials: 'omit',
      cache: 'no-store',
      headers: {
        Accept: 'application/json',
        Authorization: `Bearer ${accessToken}`,
      },
      referrerPolicy: 'no-referrer',
    })

    if (response.status === 401) {
      return { kind: 'unauthorized' }
    }

    if (response.status === 403) {
      return { kind: 'forbidden' }
    }

    if (!response.ok) {
      return { kind: 'error', message: `The API request failed with HTTP ${response.status}.` }
    }

    const body: unknown = await response.json()
    if (!isProtectedResourceResponse(body)) {
      return { kind: 'error', message: 'The API returned an unexpected response.' }
    }

    return {
      kind: 'success',
      message: body.message,
      details: `Subject ${body.subject} · Client ${body.clientId}`,
    }
  } catch {
    return { kind: 'error', message: 'The protected API could not be reached.' }
  }
}

function isProtectedResourceResponse(
  value: unknown,
): value is { message: string; subject: string; clientId: string } {
  return (
    typeof value === 'object' &&
    value !== null &&
    !Array.isArray(value) &&
    typeof (value as Record<string, unknown>).message === 'string' &&
    typeof (value as Record<string, unknown>).subject === 'string' &&
    typeof (value as Record<string, unknown>).clientId === 'string'
  )
}
