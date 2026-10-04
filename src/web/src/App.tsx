import { useState } from 'react'
import './App.css'
import { clearPendingTransaction, type ApplicationSession } from './clientState'

const identityOrigin = (import.meta.env.VITE_IDENTITY_ORIGIN ?? 'https://localhost:7443').replace(/\/$/, '')

export default function App() {
  const [applicationSession, setApplicationSession] = useState<ApplicationSession | null>(null)

  const signOutOfApp = () => {
    setApplicationSession(null)
    clearPendingTransaction()
  }

  const signOutOfIdentity = () => {
    signOutOfApp()
    window.location.assign(`${identityOrigin}/logout`)
  }

  const startSignIn = () => {
    window.location.assign(`${identityOrigin}/authorize`)
  }

  return (
    <div className="app-frame">
      <div className="aurora aurora-left" aria-hidden="true" />
      <div className="aurora aurora-right" aria-hidden="true" />
      <div className="aurora aurora-rose" aria-hidden="true" />

      <header className="topbar">
        <a className="logo" href="/" aria-label="Mini Identity client home">
          <span className="logo-symbol" aria-hidden="true"><i /><i /></span>
          <span>mini<span>identity</span></span>
        </a>
        <span className="client-badge"><i /> React application</span>
      </header>

      <main className="dashboard">
        <section className="glass intro-panel">
          <p className="eyebrow">OAuth 2.0 + OpenID Connect</p>
          <h1>Identity,<br /><span>made visible.</span></h1>
          <p className="intro-copy">
            Follow the boundary between the app's short-lived in-memory state and
            the identity server's secure browser session.
          </p>
          <button className="primary-action" type="button" onClick={startSignIn}>
            Sign in with Mini Identity <span aria-hidden="true">→</span>
          </button>
          <p className="handoff-note"><span aria-hidden="true">↗</span> Credentials are entered only at <strong>localhost:7443</strong></p>
          <div className="client-traits" aria-label="Client security traits">
            <span><i /> Browser redirect</span>
            <span><i /> Memory-only tokens</span>
          </div>
        </section>

        <section className="glass session-panel" aria-live="polite">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">Current state</p>
              <h2>Two layers of sign-in</h2>
            </div>
            <span className={`state-chip ${applicationSession ? 'active' : ''}`}><i />{applicationSession ? 'App signed in' : 'App signed out'}</span>
          </div>

          <div className="session-list">
            <article>
              <div className="session-icon app-icon" aria-hidden="true">A</div>
              <div className="session-copy">
                <h3>Application state</h3>
                <p>{applicationSession ? `Signed in as ${applicationSession.displayName ?? applicationSession.subject}.` : 'No tokens are held in this page’s memory.'}</p>
              </div>
              <button className="quiet-button" type="button" onClick={signOutOfApp}>Clear app</button>
            </article>

            <div className="boundary"><span>separate security boundary</span></div>

            <article>
              <div className="session-icon id-icon" aria-hidden="true">ID</div>
              <div className="session-copy">
                <h3>Identity-server session</h3>
                <p>Held in a Secure, HttpOnly cookie the React app cannot read.</p>
              </div>
              <button className="quiet-button danger" type="button" onClick={signOutOfIdentity}>End session</button>
            </article>
          </div>

          <div className="explain-card">
            <span className="info-dot">i</span>
            <p><strong>Why two sign-outs?</strong> Clearing app state leaves convenient identity sign-in active. Ending the identity session requires confirmation on the identity server.</p>
          </div>
        </section>
      </main>

      <footer className="app-footer">
        <span>Mini React Client</span>
        <span>Tokens: memory only · Passwords: never received</span>
      </footer>
    </div>
  )
}
