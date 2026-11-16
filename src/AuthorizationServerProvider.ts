import * as oauth from "oauth4webapi"

export interface AuthorizationServerProvider {
    getAuthorizationServer(issuer: URL, signal: AbortSignal): Promise<oauth.AuthorizationServer>
}
