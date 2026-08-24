import type { IssuerProvider } from "./IssuerProvider.js"
import * as oauth from "oauth4webapi"
import type { AuthorizationServerProvider } from "./AuthorizationServerProvider.js"

export class XASProvider implements AuthorizationServerProvider {
    readonly #issuerProvider: IssuerProvider

    constructor(issuerProvider: IssuerProvider) {
        this.#issuerProvider = issuerProvider
    }

    async getAuthorizationServer(request: Request): Promise<oauth.AuthorizationServer> {
        const issuer = await this.#issuerProvider.getIssuer(request)
        const discoveryResponse = await oauth.discoveryRequest(issuer, {signal: request.signal})
        const authorizationServer = await oauth.processDiscoveryResponse(issuer, discoveryResponse)

        return authorizationServer
    }
}
