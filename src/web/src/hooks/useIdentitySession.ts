import { useState } from 'react'
import { callProtectedResource } from '../api/protectedResource'
import type { ApiResult, Notice } from '../app/types'
import {
  clearPendingTransaction,
  oidcConfig,
  scopes,
  startAuthorization,
  type ApplicationSession,
} from '../oidc'
import { useAuthorizationCallback } from './useAuthorizationCallback'
import { useTokenExpiry } from './useTokenExpiry'

const initialNotice: Notice =
  window.location.pathname === new URL(oidcConfig.redirectUri).pathname
    ? { tone: 'progress', text: 'Reading the authorization response' }
    : { tone: 'progress', text: 'Ready for a secure redirect sign-in' }

export function useIdentitySession() {
  const [session, setSession] = useState<ApplicationSession | null>(null)
  const [selectedScope, setSelectedScope] = useState<string>(scopes.withApi)
  const [notice, setNotice] = useState<Notice>(initialNotice)
  const [apiResult, setApiResult] = useState<ApiResult>({
    tone: 'neutral',
    text: 'Sign in before calling the protected API.',
  })
  const [startingSignIn, setStartingSignIn] = useState(false)
  const [callingApi, setCallingApi] = useState(false)

  useAuthorizationCallback(setSession, setNotice, setApiResult)
  useTokenExpiry(session, setSession, setNotice, setApiResult)

  const clearAppSession = () => {
    setSession(null)
    setCallingApi(false)
    setApiResult({ tone: 'neutral', text: 'Application token state has been cleared.' })
    setNotice({ tone: 'progress', text: 'Signed out of the React application' })
    try {
      clearPendingTransaction()
    } catch {
      setNotice({ tone: 'error', text: 'Application state was cleared, but browser storage was unavailable.' })
    }
  }

  const endIdentitySession = () => {
    clearAppSession()
    window.location.assign(`${oidcConfig.issuer}/logout`)
  }

  const beginSignIn = async () => {
    setStartingSignIn(true)
    setSession(null)
    setApiResult({ tone: 'neutral', text: 'Waiting for sign-in.' })
    try {
      await startAuthorization(selectedScope, (progress) => {
        setNotice({ tone: 'progress', text: progress })
      })
    } catch {
      setStartingSignIn(false)
      setNotice({
        tone: 'error',
        text: 'Secure sign-in could not be started. Check the identity server and try again.',
      })
    }
  }

  const callApi = async () => {
    if (!session || session.expiresAt <= Date.now()) {
      setSession(null)
      setApiResult({ tone: 'error', text: 'The token has expired. Sign in again before calling the API.' })
      return
    }

    setCallingApi(true)
    setApiResult({ tone: 'neutral', text: 'Calling the protected API…' })
    const result = await callProtectedResource(session.accessToken)

    switch (result.kind) {
      case 'success':
        setApiResult({ tone: 'success', text: result.message, details: result.details })
        break
      case 'unauthorized':
        setSession(null)
        setApiResult({ tone: 'error', text: 'The API rejected the token. Sign in again to continue.' })
        setNotice({ tone: 'error', text: 'Application token state was cleared after an API 401' })
        break
      case 'forbidden':
        setApiResult({ tone: 'error', text: 'Access denied: the demo.read permission is missing.' })
        break
      case 'error':
        setApiResult({ tone: 'error', text: result.message })
        break
    }

    setCallingApi(false)
  }

  return {
    session,
    selectedScope,
    notice,
    apiResult,
    startingSignIn,
    callingApi,
    setSelectedScope,
    beginSignIn,
    callApi,
    clearAppSession,
    endIdentitySession,
  }
}
