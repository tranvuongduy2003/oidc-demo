import type { ApiResult, Notice } from '../app/types'
import type { ApplicationSession } from '../oidc'

type SessionPanelProps = {
  session: ApplicationSession | null
  notice: Notice
  apiResult: ApiResult
  callingApi: boolean
  onCallApi: () => void
  onClearAppSession: () => void
  onEndIdentitySession: () => void
}

export function SessionPanel({
  session,
  notice,
  apiResult,
  callingApi,
  onCallApi,
  onClearAppSession,
  onEndIdentitySession,
}: SessionPanelProps) {
  return (
    <section className="glass session-panel" aria-live="polite">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">Current state</p>
          <h2>Verified application session</h2>
        </div>
        <span className={`state-chip ${session ? 'active' : ''}`}><i />{session ? 'App signed in' : 'App signed out'}</span>
      </div>

      <div className={`flow-notice ${notice.tone}`} role={notice.tone === 'error' ? 'alert' : 'status'}>
        <span aria-hidden="true">{notice.tone === 'error' ? '!' : notice.tone === 'success' ? '✓' : '·'}</span>
        {notice.text}
      </div>

      <div className="identity-card">
        <div>
          <span>Verified user</span>
          <strong>{session?.displayName ?? session?.subject ?? 'No verified identity'}</strong>
          {session?.displayName && <small>Subject {session.subject}</small>}
        </div>
        <div>
          <span>Granted scopes</span>
          <strong>{session ? session.scopes.join(' · ') : '—'}</strong>
        </div>
        <div>
          <span>Token expiry</span>
          <strong>{session ? formatExpiry(session.expiresAt) : '—'}</strong>
        </div>
      </div>

      <div className={`api-card ${apiResult.tone}`}>
        <div>
          <span className="api-label">Protected API</span>
          <p>{apiResult.text}</p>
          {'details' in apiResult && <small>{apiResult.details}</small>}
        </div>
        <button
          className="quiet-button api-button"
          type="button"
          onClick={onCallApi}
          disabled={!session || callingApi}
        >
          {callingApi ? 'Calling…' : 'Call API'}
        </button>
      </div>

      <div className="session-actions">
        <button className="quiet-button" type="button" onClick={onClearAppSession} disabled={!session}>
          Clear app session
        </button>
        <button className="quiet-button danger" type="button" onClick={onEndIdentitySession}>
          End identity session
        </button>
      </div>

      <div className="explain-card">
        <span className="info-dot">i</span>
        <p><strong>Nothing sensitive is shown or persisted.</strong> Tokens stay only in page memory. Reloading the page clears them; the identity server cookie remains outside React.</p>
      </div>
    </section>
  )
}

function formatExpiry(expiresAt: number): string {
  return new Intl.DateTimeFormat(undefined, {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  }).format(expiresAt)
}
