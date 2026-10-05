const textEncoder = new TextEncoder()
const textDecoder = new TextDecoder('utf-8', { fatal: true })

export function randomBase64Url(): string {
  return encodeBase64Url(crypto.getRandomValues(new Uint8Array(32)))
}

export async function sha256Base64Url(value: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', textEncoder.encode(value))
  return encodeBase64Url(new Uint8Array(digest))
}

export function decodeJsonSegment(segment: string): unknown {
  try {
    return JSON.parse(textDecoder.decode(decodeBase64Url(segment)))
  } catch {
    throw new Error('The ID token contains invalid encoding.')
  }
}

export function decodeBase64Url(value: string): Uint8Array<ArrayBuffer> {
  if (!/^[A-Za-z0-9_-]+$/.test(value) || value.length % 4 === 1) {
    throw new Error('Invalid base64url value.')
  }

  const padding = '='.repeat((4 - (value.length % 4)) % 4)
  const decoded = atob(value.replace(/-/g, '+').replace(/_/g, '/') + padding)
  return Uint8Array.from(decoded, (character) => character.charCodeAt(0))
}

export function encodeBase64Url(value: Uint8Array): string {
  let binary = ''
  for (const byte of value) {
    binary += String.fromCharCode(byte)
  }

  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export function signingInput(header: string, payload: string): Uint8Array<ArrayBuffer> {
  return textEncoder.encode(`${header}.${payload}`)
}
