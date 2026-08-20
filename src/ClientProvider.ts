import * as oauth from "oauth4webapi"

export interface ClientProvider {
    getClient(as: oauth.AuthorizationServer, redirectUri: string, signal: AbortSignal): Promise<oauth.Client>
}
