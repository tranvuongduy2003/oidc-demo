export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

export function isNonemptyString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0
}

export function isNumericDate(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0
}

export function isBoundedDisplayValue(value: string): boolean {
  return value.length > 0 && value.length <= 512 && !/\p{Cc}/u.test(value)
}

export function messageFrom(error: unknown, fallback: string): string {
  return error instanceof Error && error.message ? error.message : fallback
}
