import * as oauth from "oauth4webapi"
import type { AuthorizationServerProvider } from "./AuthorizationServerProvider.js"

export class DiscoveryAuthorizationServerProvider implements AuthorizationServerProvider {
    readonly #options: oauth.HttpRequestOptions<string, any> | undefined

    constructor(options?: oauth.HttpRequestOptions<string, any>) {
        this.#options = options
    }

    async getAuthorizationServer(issuer: URL, signal: AbortSignal): Promise<oauth.AuthorizationServer> {
        const discoveryResponse = await oauth.discoveryRequest(issuer, {...this.#options, signal})
        const authorizationServer = await oauth.processDiscoveryResponse(issuer, discoveryResponse)

        return authorizationServer
    }
}
