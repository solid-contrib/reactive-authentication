import * as oauth from "oauth4webapi"
import type { AuthorizationServerProvider } from "./AuthorizationServerProvider.js"

export class DiscoveryAuthorizationServerProvider implements AuthorizationServerProvider {
    async getAuthorizationServer(issuer: URL, signal: AbortSignal): Promise<oauth.AuthorizationServer> {
        const discoveryResponse = await oauth.discoveryRequest(issuer, {signal})
        const authorizationServer = await oauth.processDiscoveryResponse(issuer, discoveryResponse)

        return authorizationServer
    }
}
