import * as oauth from "oauth4webapi"
import type { AuthorizationServerProvider } from "./AuthorizationServerProvider.js"

export class DiscoveryAuthorizationServerProvider implements AuthorizationServerProvider {
    readonly #options: oauth.HttpRequestOptions<string, any> | undefined
    readonly #algorithm: "oidc" | "oauth2"

    constructor(options?: oauth.HttpRequestOptions<string, any>, algorithm: "oidc" | "oauth2" = "oidc") {
        this.#options = options
        this.#algorithm = algorithm
    }

    async getAuthorizationServer(issuer: URL, signal: AbortSignal): Promise<oauth.AuthorizationServer> {
        const discoveryResponse = await oauth.discoveryRequest(issuer, {...this.#options, algorithm: this.#algorithm, signal})
        const authorizationServer = await oauth.processDiscoveryResponse(issuer, discoveryResponse)

        return authorizationServer
    }
}
