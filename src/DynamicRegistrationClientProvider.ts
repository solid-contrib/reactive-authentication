import type { ClientProvider } from "./ClientProvider.js"
import * as oauth from "oauth4webapi"
import { supportsOfflineAccess } from "./supportsOfflineAccess.js"

export class DynamicRegistrationClientProvider implements ClientProvider {
    async getClient(as: oauth.AuthorizationServer, redirectUri: string, signal: AbortSignal): Promise<oauth.Client> {
        const metadata = {
            redirect_uris: [redirectUri],
            grant_types: ["authorization_code"]
        }

        if (supportsOfflineAccess(as)) {
            metadata.grant_types.push("refresh_token")
        }

        const registrationResponse = await oauth.dynamicClientRegistrationRequest(as, metadata, {signal})
        const client = await oauth.processDynamicClientRegistrationResponse(registrationResponse)

        return client
    }
}
