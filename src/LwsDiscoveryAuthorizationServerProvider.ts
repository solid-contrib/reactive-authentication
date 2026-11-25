import * as oauth from "oauth4webapi"
import type {AuthorizationServerProvider} from "./AuthorizationServerProvider.js"

/**
 * Discovers authorization server metadata at the `/.well-known/lws-configuration` path as defined in {@link https://www.w3.org/TR/2026/WD-lws10-core-20260331/#x5-2-2-authorization-server-metadata LWS 1.0 Core § 5.2.2 Authorization Server Metadata}.
 *
 * Following {@link https://www.rfc-editor.org/rfc/rfc8414#section-3 RFC 8414 § 3}, the well-known path is inserted between the host and the path of the issuer. The issuer `https://as.example/tenant` is therefore requested from `https://as.example/.well-known/lws-configuration/tenant`. The response is validated with {@link https://www.rfc-editor.org/rfc/rfc8414#section-3.3 RFC 8414 § 3.3}.
 *
 * Any unsuccessful response throws an `OperationProcessingError` whose `cause` is the `Response`, so callers can inspect the HTTP status.
 */
export class LwsDiscoveryAuthorizationServerProvider implements AuthorizationServerProvider {
    readonly #options: oauth.HttpRequestOptions<string, any> | undefined

    constructor(options?: oauth.HttpRequestOptions<string, any>) {
        this.#options = options
    }

    async getAuthorizationServer(issuer: URL, signal: AbortSignal): Promise<oauth.AuthorizationServer> {
        // LWS 1.0 Core § 5.2.2 defines the lws-configuration well-known path, which oauth.discoveryRequest cannot request: it supports only the oidc and oauth2 well-known paths and has no custom path option. This provider therefore builds the request itself and still validates the response with oauth.processDiscoveryResponse.

        // Same protocol check that oauth.discoveryRequest performs: HTTPS only, unless allowInsecureRequests is set.
        oauth.checkProtocol(issuer, this.#options?.[oauth.allowInsecureRequests] !== true)

        const url = new URL(issuer.href)
        url.pathname = url.pathname === "/"
            ? "/.well-known/lws-configuration"
            : `/.well-known/lws-configuration${url.pathname.replace(/\/$/, "")}`

        const fetchImplementation = this.#options?.[oauth.customFetch] ?? fetch
        const response = await fetchImplementation(url.href, {
            // The custom fetch type requires a body property.
            body: null,
            headers: {accept: "application/json"},
            method: "GET",
            // Same as oauth.discoveryRequest: a redirect is not a valid metadata response and is not followed.
            redirect: "manual",
            signal,
        })

        return await oauth.processDiscoveryResponse(issuer, response)
    }
}
