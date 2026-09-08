import type { ClientProvider } from "./ClientProvider.js"
import * as oauth from "oauth4webapi"

export class DynamicRegistrationClientProvider implements ClientProvider {
    async getClient(as: oauth.AuthorizationServer, redirectUri: string, signal: AbortSignal): Promise<oauth.Client> {
        const metadata = {
            redirect_uris: [redirectUri],
        }

        const registrationResponse = await oauth.dynamicClientRegistrationRequest(as, metadata, {signal})
        const client = await oauth.processDynamicClientRegistrationResponse(registrationResponse)

        return client
    }
}
