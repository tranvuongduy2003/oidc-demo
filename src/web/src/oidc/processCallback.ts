import { describeAuthorizationError, readAndRemoveCallbackParameters } from './callbackParameters'
import { oidcConfig } from './config'
import { loadTrustedMetadata } from './discovery'
import { messageFrom } from './guards'
import { redeemCode } from './tokenEndpoint'
import { validateTokenResponse } from './tokenResponseValidator'
import {
  isFreshTransaction,
  readPendingTransaction,
  safelyClearPendingTransaction,
} from './transactionStore'
import type { CallbackResult, FlowProgress, PendingTransaction } from './types'

let callbackProcessingPromise: Promise<CallbackResult> | null = null

export function processAuthorizationCallback(
  onProgress: (progress: FlowProgress) => void,
): Promise<CallbackResult> {
  callbackProcessingPromise ??= processAuthorizationCallbackOnce(onProgress)
  return callbackProcessingPromise
}

async function processAuthorizationCallbackOnce(
  onProgress: (progress: FlowProgress) => void,
): Promise<CallbackResult> {
  if (window.location.pathname !== new URL(oidcConfig.redirectUri).pathname) {
    return { kind: 'none' }
  }

  onProgress('Checking the authorization response')
  const callback = readAndRemoveCallbackParameters()

  let transaction: PendingTransaction | null
  try {
    transaction = readPendingTransaction()
  } catch {
    return { kind: 'error', message: 'The pending sign-in could not be read. Start a new sign-in.' }
  }

  if (!transaction || !isFreshTransaction(transaction)) {
    safelyClearPendingTransaction()
    return { kind: 'error', message: 'This sign-in request is missing or has expired. Start again.' }
  }

  if (!callback.state || callback.state !== transaction.state) {
    safelyClearPendingTransaction()
    return { kind: 'error', message: 'The authorization response did not match this sign-in request.' }
  }

  if (callback.error !== null) {
    safelyClearPendingTransaction()
    if (callback.code !== null) {
      return { kind: 'error', message: 'The authorization response contained conflicting results.' }
    }

    return {
      kind: 'error',
      message: describeAuthorizationError(callback.error, callback.errorDescription),
    }
  }

  if (!callback.code) {
    safelyClearPendingTransaction()
    return { kind: 'error', message: 'The authorization response did not contain a code.' }
  }

  safelyClearPendingTransaction()

  let metadata
  try {
    onProgress('Checking provider metadata')
    metadata = await loadTrustedMetadata()
  } catch (error) {
    return { kind: 'error', message: messageFrom(error, 'The identity provider could not be verified.') }
  }

  let tokenResponse: unknown
  try {
    onProgress('Redeeming the one-time code')
    tokenResponse = await redeemCode(metadata.tokenEndpoint, callback.code, transaction.verifier)
  } catch (error) {
    return {
      kind: 'error',
      message: messageFrom(
        error,
        'The token request may not have completed. It will not be retried; start a new sign-in.',
      ),
    }
  }

  try {
    onProgress('Validating the ID token signature and claims')
    const session = await validateTokenResponse(tokenResponse, transaction.nonce, metadata.jwksUri)
    return { kind: 'success', session }
  } catch (error) {
    return {
      kind: 'error',
      message: messageFrom(error, 'The returned identity token was not valid.'),
    }
  }
}
