import { useEffect, type Dispatch, type SetStateAction } from 'react'
import type { ApiResult, Notice } from '../app/types'
import type { ApplicationSession } from '../oidc'

export function useTokenExpiry(
  session: ApplicationSession | null,
  setSession: Dispatch<SetStateAction<ApplicationSession | null>>,
  setNotice: Dispatch<SetStateAction<Notice>>,
  setApiResult: Dispatch<SetStateAction<ApiResult>>,
) {
  useEffect(() => {
    if (!session) {
      return
    }

    const expiryTimer = window.setTimeout(() => {
      setSession(null)
      setApiResult({ tone: 'error', text: 'The token expired. Sign in again to call the API.' })
      setNotice({ tone: 'error', text: 'Your application session expired' })
    }, Math.max(0, session.expiresAt - Date.now()))

    return () => window.clearTimeout(expiryTimer)
  }, [session, setApiResult, setNotice, setSession])
}
