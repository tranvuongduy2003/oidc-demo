import './App.css'
import { SessionPanel } from './components/SessionPanel'
import { SignInPanel } from './components/SignInPanel'
import { useIdentitySession } from './hooks/useIdentitySession'

export default function App() {
  const identity = useIdentitySession()

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

      <main className={`dashboard ${identity.session ? 'dashboard-authenticated' : ''}`}>
        {!identity.session && (
          <SignInPanel
            selectedScope={identity.selectedScope}
            startingSignIn={identity.startingSignIn}
            onScopeChange={identity.setSelectedScope}
            onStartSignIn={identity.beginSignIn}
          />
        )}
        <SessionPanel
          session={identity.session}
          notice={identity.notice}
          apiResult={identity.apiResult}
          callingApi={identity.callingApi}
          onCallApi={identity.callApi}
          onClearAppSession={identity.clearAppSession}
          onEndIdentitySession={identity.endIdentitySession}
        />
      </main>

      <footer className="app-footer">
        <span>Mini React Client</span>
        <span>Tokens: memory only · Passwords: never received</span>
      </footer>
    </div>
  )
}
