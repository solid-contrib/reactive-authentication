import * as oauth from "oauth4webapi"

export type GetClientCallback = (as: oauth.AuthorizationServer, redirectUri: string, signal: AbortSignal) => Promise<oauth.Client>
