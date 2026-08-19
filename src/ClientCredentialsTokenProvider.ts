import * as oauth from "oauth4webapi"
import { AuthorizationServer } from "oauth4webapi"
import * as DPoP from "dpop"
import type { TokenProvider } from "./TokenProvider.js"
import { InsecureConfiguration } from "./InsecureConfiguration.js"

export class ClientCredentialsTokenProvider implements TokenProvider {
    constructor(private clientId: string, private clientSecret: string) {
    }

    async #getIssuer(request: Request): Promise<URL> {
        if (request.url.includes(".solidcommunity.net")) {
            return new URL("https://solidcommunity.net")
        } else if (request.url.includes("datapod.igrant.io")) {
            return new URL("https://datapod.igrant.io")
        } else if (request.url.includes(".solidweb.app")) {
            return new URL("https://solidweb.app")
        } else if (request.url.includes("storage.inrupt.com")) {
            return new URL("https://login.inrupt.com")
        } else if (request.url.includes("teamid.live")) {
            return new URL("https://teamid.live")
        } else if (request.url.includes(".solidweb.org")) {
            return new URL("https://solidweb.org")
        } else if (request.url.includes("localhost:3000")) {
            return new URL("http://localhost:3000")
        } else {
            throw new Error(`Unknown issuer ${request.url}`)
        }
    }

    async matches(request: Request): Promise<boolean> {
        return true
    }

    async upgrade(request: Request): Promise<Request> {
        const issuer = await this.#getIssuer(request)

        const discoveryResponse = await oauth.discoveryRequest(issuer, {
            signal: request.signal,
            ...InsecureConfiguration.requestOptions
        })
        const authorizationServer = await oauth.processDiscoveryResponse(issuer, discoveryResponse)

        const clientRegistration: oauth.Client = {client_id: this.clientId, client_secret: this.clientSecret}

        const dpopKey = await oauth.generateKeyPair("ES256", {extractable: false}) // TODO: Align with dpop_signing_alg_values_supported and fallback
        const dpop = oauth.DPoP({}, dpopKey)

        const tokenResponse = await oauth.clientCredentialsGrantRequest(authorizationServer, clientRegistration, this.getClientAuth(authorizationServer, clientRegistration), {scope: "webid"}, {
            DPoP: dpop,
            signal: request.signal,
            ...InsecureConfiguration.requestOptions
        })

        const tokenResult = await oauth.processClientCredentialsResponse(authorizationServer, clientRegistration, tokenResponse)

        const headers = new Headers(request.headers)

        headers.set("DPoP", await DPoP.generateProof(dpopKey, request.url, request.method, undefined, tokenResult.access_token))
        headers.set("Authorization", ["DPoP", tokenResult.access_token].join(" "))

        return new Request(request, {headers})
    }

    private getClientAuth(authorizationServer: AuthorizationServer, client: oauth.OmitSymbolProperties<oauth.Client>): oauth.ClientAuth {
        const clientSecret = client.client_secret as string

        // if (authorizationServer.token_endpoint_auth_methods_supported?.includes("client_secret_jwt")) {
        //     return oauth.ClientSecretJwt(clientSecret)
        // }

        // if (authorizationServer.token_endpoint_auth_methods_supported?.includes("client_secret_post")) {
        //     return oauth.ClientSecretPost(clientSecret)
        // }

        if (authorizationServer.token_endpoint_auth_methods_supported?.includes("client_secret_basic")) {
            const clientSecretBasic = clientSecretBasicFor(authorizationServer.issuer)
            return clientSecretBasic(clientSecret)
        }

        throw new Error("Could not find client authentication method in authorization server metadata")
    }
}

/**
 * A variation of the original from oauth4webapi that does not url encode Id and secret.
 *
 * @remarks PodSpaces (ESS) seems to fail when spec is followed.
 *
 * @see Original code at https://github.com/panva/oauth4webapi/blob/b914d175a58a1738b65a360dc2f28d6c0f88a720/src/index.ts#L1777
 * @see Spec https://www.rfc-editor.org/rfc/rfc6749.html#section-2.3.1
 */
function NoUrlEncodeClientSecretBasic(clientSecret: string): oauth.ClientAuth {
    return function (_, client, __, headers) {
        console.debug("Using non-conforming (no url encoding) client secret basic token authentication")
        headers.set("Authorization", `Basic ${btoa(`${client.client_id}:${clientSecret}`)}`);
    };
}

function clientSecretBasicFor(issuer: string): (clientSecret: string) => oauth.ClientAuth {
    // TODO: Better fingerprinting ESS
    if (issuer.includes("login.inrupt.com")) {
        console.debug("Using token authentication workaround for ESS")
        return NoUrlEncodeClientSecretBasic
    }

    return oauth.ClientSecretBasic
}
