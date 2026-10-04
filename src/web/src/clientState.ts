export const pendingTransactionKey = 'mini-identity:authorization-transaction'

export type ApplicationSession = {
  subject: string
  displayName?: string
  scopes: string[]
  expiresAt: number
}

export function clearPendingTransaction() {
  sessionStorage.removeItem(pendingTransactionKey)
}
