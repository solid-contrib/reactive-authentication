import * as oauth from "oauth4webapi"

export interface AuthorizationServerProvider {
    getAuthorizationServer(request: Request): Promise<oauth.AuthorizationServer>
}
