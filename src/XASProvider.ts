import type { GetIssuerCallback } from "./GetIssuerCallback.js"
import type { AuthorizationServer } from "oauth4webapi"
import * as oauth from "oauth4webapi"
import type { AuthorizationServerProvider } from "./AuthorizationServerProvider.js"

export class XASProvider implements AuthorizationServerProvider {
    readonly #getIssuer: GetIssuerCallback

    constructor(getIssuerCallback: GetIssuerCallback) {
        this.#getIssuer = getIssuerCallback
    }

    async getAuthorizationServer(request: Request): Promise<AuthorizationServer> {
        const issuer = await this.#getIssuer(request)
        const discoveryResponse = await oauth.discoveryRequest(issuer, {signal: request.signal})
        const authorizationServer = await oauth.processDiscoveryResponse(issuer, discoveryResponse)

        return authorizationServer
    }
}
