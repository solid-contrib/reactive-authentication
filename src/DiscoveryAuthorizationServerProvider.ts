import type { IssuerProvider } from "./IssuerProvider.js"
import * as oauth from "oauth4webapi"
import type { AuthorizationServerProvider } from "./AuthorizationServerProvider.js"

export class DiscoveryAuthorizationServerProvider implements AuthorizationServerProvider {
    readonly #issuerProvider: IssuerProvider
    readonly #options: oauth.HttpRequestOptions<string, any> | undefined

    constructor(issuerProvider: IssuerProvider, options?: oauth.HttpRequestOptions<string, any>) {
        this.#issuerProvider = issuerProvider
        this.#options = options
    }

    async getAuthorizationServer(request: Request): Promise<oauth.AuthorizationServer> {
        const issuer = await this.#issuerProvider.getIssuer(request)
        const discoveryResponse = await oauth.discoveryRequest(issuer, {...this.#options, signal: request.signal})
        const authorizationServer = await oauth.processDiscoveryResponse(issuer, discoveryResponse)

        return authorizationServer
    }
}
