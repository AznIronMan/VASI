import type { AuthProviderReadiness } from "@/lib/auth-providers";

export function ProviderReadinessPanel({ providers }: { providers: AuthProviderReadiness[] }) {
  return <section className="provider-readiness" aria-labelledby="provider-readiness-title">
    <div className="provider-readiness__heading">
      <div>
        <p className="eyebrow eyebrow--green">SIGN-IN PROVIDERS</p>
        <h2 id="provider-readiness-title">Activation readiness</h2>
        <p>Credential values are never shown. Register both callback URLs before enabling a provider for public or internal use.</p>
      </div>
      <span>{providers.filter((provider) => provider.status === "ready").length} of {providers.length} ready</span>
    </div>
    <div className="provider-readiness__grid">
      {providers.map((provider) => <article key={provider.id}>
        <div className="provider-readiness__provider">
          <i className={`provider-readiness__light provider-readiness__light--${provider.status}`} aria-hidden="true" />
          <div>
            <strong>{provider.label}</strong>
            <span>{providerStatus(provider)}</span>
          </div>
        </div>
        <dl>
          <div>
            <dt>Public callback</dt>
            <dd><code>{provider.publicCallback}</code></dd>
          </div>
          <div>
            <dt>Internal callback</dt>
            <dd><code>{provider.adminCallback}</code></dd>
          </div>
        </dl>
      </article>)}
    </div>
    <p className="provider-readiness__note">
      Update provider credentials through protected VASI settings, run settings validation, then restart the gateway. A partial tuple or unsupported Zoho account origin is rejected before authentication starts.
    </p>
  </section>;
}

function providerStatus(provider: AuthProviderReadiness) {
  if (provider.status === "ready") return "Configured and visible";
  if (provider.status === "hidden") {
    return provider.configured
      ? "Configured, intentionally hidden"
      : "Hidden; configuration required";
  }
  if (provider.status === "invalid") return "Invalid partial configuration";
  return "Configuration required";
}
