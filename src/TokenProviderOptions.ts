/**
 * Options accepted by the token providers.
 */
export interface TokenProviderOptions {
    /**
     * The fetch implementation the provider uses for its own OIDC requests —
     * discovery, dynamic client registration and the token grant.
     *
     * @remarks
     * Defaults to `globalThis.fetch`, resolved at call time (oauth4webapi's
     * default behaviour).
     *
     * Applications that patch the global fetch with an authenticating wrapper
     * (`ReactiveFetchManager.registerGlobally()`, or their own wrapper that
     * single-flights concurrent requests onto one shared authentication
     * attempt) should pass the pristine, pre-patch fetch here. Otherwise the
     * provider's own OIDC requests re-enter the wrapper mid-upgrade: a
     * single-flighting wrapper then awaits the very authentication attempt
     * those requests are serving — a circular await that hangs login before
     * the authorization redirect/popup ever opens.
     */
    fetch?: typeof globalThis.fetch
}
