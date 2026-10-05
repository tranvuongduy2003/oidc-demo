import { oidcConfig, scopes } from './config'
import { loadTrustedMetadata } from './discovery'
import {
  replacePendingTransaction,
  safelyClearPendingTransaction,
} from './transactionStore'
import type { FlowProgress, PendingTransaction } from './types'
import { randomBase64Url, sha256Base64Url } from './values'

export async function startAuthorization(
  scope: string,
  onProgress: (progress: FlowProgress) => void,
): Promise<void> {
  safelyClearPendingTransaction()
  if (scope !== scopes.withApi && scope !== scopes.identityOnly) {
    throw new Error('The requested scope set is not allowed by this client.')
  }

  onProgress('Checking provider metadata')
  const metadata = await loadTrustedMetadata()

  onProgress('Creating a protected sign-in request')
  const transaction: PendingTransaction = {
    state: randomBase64Url(),
    nonce: randomBase64Url(),
    verifier: randomBase64Url(),
    createdAt: Date.now(),
  }
  const challenge = await sha256Base64Url(transaction.verifier)

  replacePendingTransaction(transaction)

  const authorizationUrl = new URL(metadata.authorizationEndpoint)
  authorizationUrl.search = new URLSearchParams({
    client_id: oidcConfig.clientId,
    redirect_uri: oidcConfig.redirectUri,
    response_type: 'code',
    response_mode: 'query',
    scope,
    state: transaction.state,
    nonce: transaction.nonce,
    code_challenge: challenge,
    code_challenge_method: 'S256',
  }).toString()

  onProgress('Opening the identity server')
  window.location.assign(authorizationUrl)
}
