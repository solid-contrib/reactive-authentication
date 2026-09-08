import * as oauth from "oauth4webapi"

export function supportsOfflineAccess(as: oauth.AuthorizationServer) {
    return as.scopes_supported === undefined || as.scopes_supported.includes("offline_access")
}
