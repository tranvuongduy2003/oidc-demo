import { oidcConfig, scopes } from '../oidc'

type SignInPanelProps = {
  selectedScope: string
  startingSignIn: boolean
  onScopeChange: (scope: string) => void
  onStartSignIn: () => void
}

export function SignInPanel({
  selectedScope,
  startingSignIn,
  onScopeChange,
  onStartSignIn,
}: SignInPanelProps) {
  return (
    <section className="glass intro-panel">
      <p className="eyebrow">OAuth 2.0 + OpenID Connect</p>
      <h1>Identity,<br /><span>made visible.</span></h1>
      <p className="intro-copy">
        Choose whether this app may call the demo API. Your password is entered only on the
        identity server.
      </p>

      <fieldset className="scope-picker" disabled={startingSignIn}>
        <legend>Permission set</legend>
        <label className={selectedScope === scopes.withApi ? 'selected' : ''}>
          <input
            type="radio"
            name="scope"
            value={scopes.withApi}
            checked={selectedScope === scopes.withApi}
            onChange={() => onScopeChange(scopes.withApi)}
          />
          <span><strong>Sign in + API access</strong><small>openid · profile · demo.read</small></span>
        </label>
        <label className={selectedScope === scopes.identityOnly ? 'selected' : ''}>
          <input
            type="radio"
            name="scope"
            value={scopes.identityOnly}
            checked={selectedScope === scopes.identityOnly}
            onChange={() => onScopeChange(scopes.identityOnly)}
          />
          <span><strong>Sign in only</strong><small>openid · profile</small></span>
        </label>
      </fieldset>

      <button className="primary-action" type="button" onClick={onStartSignIn} disabled={startingSignIn}>
        {startingSignIn ? 'Preparing secure sign-in…' : 'Sign in with Mini Identity'}
        <span aria-hidden="true">→</span>
      </button>
      <p className="handoff-note"><span aria-hidden="true">↗</span> Credentials are entered only at <strong>{new URL(oidcConfig.issuer).host}</strong></p>
      <div className="client-traits" aria-label="Client security traits">
        <span><i /> Browser redirect</span>
        <span><i /> Memory-only tokens</span>
        <span><i /> Web Crypto verified</span>
      </div>
    </section>
  )
}
