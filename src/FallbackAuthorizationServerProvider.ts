import * as oauth from "oauth4webapi"
import type {AuthorizationServerProvider} from "./AuthorizationServerProvider.js"

/**
 * Uses a fallback provider when the primary provider fails because the metadata resource was not found (HTTP 404).
 *
 * It exists for authorization servers that do not serve the `/.well-known/lws-configuration` path required by {@link https://www.w3.org/TR/2026/WD-lws10-core-20260331/#x5-2-2-authorization-server-metadata LWS 1.0 Core § 5.2.2 Authorization Server Metadata}. For example, Inrupt ESS returns 404 there and serves only the {@link https://www.rfc-editor.org/rfc/rfc8414#section-3 RFC 8414 § 3} metadata at `/.well-known/oauth-authorization-server`. This is a workaround for a deviation from LWS 1.0 Core.
 *
 * Any other error from the primary provider is rethrown.
 */
export class FallbackAuthorizationServerProvider implements AuthorizationServerProvider {
    readonly #primary: AuthorizationServerProvider
    readonly #fallback: AuthorizationServerProvider

    constructor(primary: AuthorizationServerProvider, fallback: AuthorizationServerProvider) {
        this.#primary = primary
        this.#fallback = fallback
    }

    async getAuthorizationServer(issuer: URL, signal: AbortSignal): Promise<oauth.AuthorizationServer> {
        try {
            return await this.#primary.getAuthorizationServer(issuer, signal)
        } catch (error) {
            if (error instanceof oauth.OperationProcessingError
                && error.code === oauth.RESPONSE_IS_NOT_CONFORM
                && error.cause instanceof Response
                && error.cause.status === 404) {
                return await this.#fallback.getAuthorizationServer(issuer, signal)
            }

            throw error
        }
    }
}
