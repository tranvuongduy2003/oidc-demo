import { isBoundedDisplayValue } from './guards'
import { safelyClearPendingTransaction } from './transactionStore'

export type CallbackParameters = {
  code: string | null
  error: string | null
  errorDescription: string | null
  state: string | null
}

export function readAndRemoveCallbackParameters(): CallbackParameters {
  const parameters = new URLSearchParams(window.location.search)
  const counts = new Map<string, number>()
  for (const name of parameters.keys()) {
    counts.set(name, (counts.get(name) ?? 0) + 1)
  }

  window.history.replaceState({}, document.title, window.location.pathname)

  if ([...counts.values()].some((count) => count !== 1)) {
    safelyClearPendingTransaction()
    throw new Error('The authorization response contained duplicate parameters.')
  }

  return {
    code: parameters.get('code'),
    error: parameters.get('error'),
    errorDescription: parameters.get('error_description'),
    state: parameters.get('state'),
  }
}

export function describeAuthorizationError(error: string, description: string | null): string {
  if (error === 'access_denied') {
    return 'Sign-in was cancelled at the identity server.'
  }

  const safeError = isBoundedDisplayValue(error) ? error : 'invalid_response'
  const safeDescription = description && isBoundedDisplayValue(description) ? ` ${description}` : ''
  return `The identity server returned ${safeError}.${safeDescription}`
}
