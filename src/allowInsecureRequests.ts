import * as oauth from "oauth4webapi"

let warned = false

/**
 * Creates options that allow OAuth requests over plain HTTP (`http:` endpoints).
 *
 * @remarks
 * Deprecated on purpose, so that consumers see the security implication at the call site.
 * Only for local development servers; never use in production.
 * Logs a warning to the console the first time it is called.
 *
 * @example
 * ```ts
 * new DiscoveryAuthorizationServerProvider(issuerProvider, allowInsecureRequests())
 * ```
 *
 * @see {@link oauth.allowInsecureRequests}
 * @see https://github.com/panva/oauth4webapi/blob/main/docs/variables/allowInsecureRequests.md
 * @deprecated Only ever call this in local development.
 */
export function allowInsecureRequests(): oauth.HttpRequestOptions<string, any> {
    if (!warned) {
        warned = true
        console.warn("Insecure (plain HTTP) OAuth requests are allowed. Use for local development only.")
    }

    return {[oauth.allowInsecureRequests]: true}
}
