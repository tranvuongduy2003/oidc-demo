import { useEffect, type Dispatch, type SetStateAction } from 'react'
import type { ApiResult, Notice } from '../app/types'
import {
  processAuthorizationCallback,
  type ApplicationSession,
  type FlowProgress,
} from '../oidc'

export function useAuthorizationCallback(
  setSession: Dispatch<SetStateAction<ApplicationSession | null>>,
  setNotice: Dispatch<SetStateAction<Notice>>,
  setApiResult: Dispatch<SetStateAction<ApiResult>>,
) {
  useEffect(() => {
    let active = true
    const reportProgress = (progress: FlowProgress) => {
      if (active) {
        setNotice({ tone: 'progress', text: progress })
      }
    }

    void processAuthorizationCallback(reportProgress)
      .then((result) => {
        if (!active || result.kind === 'none') {
          return
        }

        if (result.kind === 'success') {
          setSession(result.session)
          setApiResult({ tone: 'neutral', text: 'Identity verified. The API has not been called yet.' })
          setNotice({ tone: 'success', text: 'Sign-in complete and ID token verified' })
          return
        }

        setSession(null)
        setNotice({ tone: 'error', text: result.message })
      })
      .catch(() => {
        if (active) {
          setSession(null)
          setNotice({
            tone: 'error',
            text: 'The authorization response was malformed. Start a new sign-in.',
          })
        }
      })

    return () => {
      active = false
    }
  }, [setApiResult, setNotice, setSession])
}
