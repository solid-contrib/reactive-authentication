import * as oauth from "oauth4webapi"

export async function dynamicRegistrationClientCallback(as: oauth.AuthorizationServer, redirectUri: string, signal: AbortSignal): Promise<oauth.Client> {
    const registrationResponse = await oauth.dynamicClientRegistrationRequest(as, {redirect_uris: [redirectUri]}, {signal})
    return await oauth.processDynamicClientRegistrationResponse(registrationResponse)
}
