import { isRecord } from './guards'
import type { PendingTransaction } from './types'

const pendingTransactionKey = 'mini-identity:authorization-transaction'
const transactionLifetimeMs = 5 * 60 * 1000

export function clearPendingTransaction() {
  sessionStorage.removeItem(pendingTransactionKey)
}

export function safelyClearPendingTransaction() {
  try {
    clearPendingTransaction()
  } catch {
    // The one-shot callback promise still prevents a retry in this page load.
  }
}

export function replacePendingTransaction(transaction: PendingTransaction) {
  sessionStorage.setItem(pendingTransactionKey, JSON.stringify(transaction))
}

export function readPendingTransaction(): PendingTransaction | null {
  const serialized = sessionStorage.getItem(pendingTransactionKey)
  if (serialized === null) {
    return null
  }

  try {
    const value: unknown = JSON.parse(serialized)
    if (!isRecord(value)) {
      return null
    }

    const keys = Object.keys(value).sort()
    const expectedKeys = ['createdAt', 'nonce', 'state', 'verifier']
    if (
      keys.length !== expectedKeys.length ||
      keys.some((key, index) => key !== expectedKeys[index]) ||
      typeof value.state !== 'string' ||
      typeof value.nonce !== 'string' ||
      typeof value.verifier !== 'string' ||
      typeof value.createdAt !== 'number'
    ) {
      return null
    }

    return {
      state: value.state,
      nonce: value.nonce,
      verifier: value.verifier,
      createdAt: value.createdAt,
    }
  } catch {
    return null
  }
}

export function isFreshTransaction(transaction: PendingTransaction): boolean {
  const age = Date.now() - transaction.createdAt
  return (
    Number.isSafeInteger(transaction.createdAt) &&
    age >= 0 &&
    age < transactionLifetimeMs &&
    /^[A-Za-z0-9_-]{43}$/.test(transaction.state) &&
    /^[A-Za-z0-9_-]{43}$/.test(transaction.nonce) &&
    /^[A-Za-z0-9_-]{43}$/.test(transaction.verifier)
  )
}
