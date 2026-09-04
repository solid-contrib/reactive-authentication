import type { ClientProvider } from "./ClientProvider.js"
import * as oauth from "oauth4webapi"

export class ClientIdClientProvider implements ClientProvider {
    constructor(private clientIdDocUri: URL) {
    }

    async getClient(_: oauth.AuthorizationServer, __: string, signal: AbortSignal): Promise<oauth.Client> {
        const response = await fetch(this.clientIdDocUri, {signal})
        return await response.json()
    }
}
