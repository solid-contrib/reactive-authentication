import * as oauth from "oauth4webapi"
import type { GetCodeCallback } from "./GetCodeCallback.js"
import type { TokenProvider } from "./TokenProvider.js"

export class DPoPTokenProvider implements TokenProvider {
    readonly #getCode: GetCodeCallback

    constructor(getCodeCallback: GetCodeCallback) {
        this.#getCode = getCodeCallback
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

    async #getCallback(request: Request): Promise<string> {
        return "http://localhost:8080/callback.html"
    }

    async matches(request: Request): Promise<boolean> {
        return true
    }

    async upgrade(request: Request): Promise<Request> {
        const issuer = await this.#getIssuer(request)

        // const discoveryResponse = await oauth.discoveryRequest(issuer)
        const discoveryResponse = await oauth.discoveryRequest(issuer, {[oauth.allowInsecureRequests]: true})
        const authorizationServer = await oauth.processDiscoveryResponse(issuer, discoveryResponse)

        const callbackUri = await this.#getCallback(request)

        // const registrationResponse = await oauth.dynamicClientRegistrationRequest(authorizationServer, {redirect_uris: [callbackUri]})
        const registrationResponse = await oauth.dynamicClientRegistrationRequest(authorizationServer, {redirect_uris: [callbackUri]}, {[oauth.allowInsecureRequests]: true})
        const clientRegistration = await oauth.processDynamicClientRegistrationResponse(registrationResponse)
        const [registeredRedirectUri] = clientRegistration.redirect_uris as string[]
        const [registeredResponseType] = clientRegistration.response_types as string[]
        const clientSecret = clientRegistration.client_secret as string

        const dpopKey = await crypto.subtle.generateKey({name: "ECDSA", namedCurve: "P-256"}, true, ["sign"])
        const dpop = oauth.DPoP({}, dpopKey)

        const codeVerifier = oauth.generateRandomCodeVerifier()
        const codeChallenge = await oauth.calculatePKCECodeChallenge(codeVerifier)

        // TODO: support prompt=none
        const authorizationUrl = new URL(authorizationServer.authorization_endpoint!)
        authorizationUrl.searchParams.set("client_id", clientRegistration.client_id)
        authorizationUrl.searchParams.set("redirect_uri", registeredRedirectUri!)
        authorizationUrl.searchParams.set("response_type", registeredResponseType!)
        authorizationUrl.searchParams.set("scope", "openid webid")
        // authorizationUrl.searchParams.set("prompt", "consent")
        authorizationUrl.searchParams.set("code_challenge", codeChallenge)
        authorizationUrl.searchParams.set("code_challenge_method", "S256")


        // igrant (nss) seems to not return nonce
        // let nonce
        // if (authorizationServer.code_challenge_methods_supported?.includes("S256") !== true) {
        //     nonce = oauth.generateRandomNonce()
        //     authorizationUrl.searchParams.set("nonce", nonce)
        // }

        const authorizationCodeResponse = await this.#getCode(authorizationUrl)
        const authorizationCodeParams = oauth.validateAuthResponse(authorizationServer, clientRegistration, new URL(authorizationCodeResponse))

        let clientAuth = oauth.None()
        if (clientRegistration.token_endpoint_auth_method === "client_secret_basic") {
            const authenticationMethod = authenticationMethodFor(authorizationServer.issuer!)
            clientAuth = authenticationMethod(clientSecret)
        }

        // const tokenResponse = await oauth.authorizationCodeGrantRequest(authorizationServer, clientRegistration, clientAuth, authorizationCodeParams, callbackUri, codeVerifier, {DPoP: dpop})
        const tokenResponse = await oauth.authorizationCodeGrantRequest(authorizationServer, clientRegistration, clientAuth, authorizationCodeParams, callbackUri, codeVerifier, {
            DPoP: dpop,
            [oauth.allowInsecureRequests]: true
        })

        // jwt nonce missing in igrant
        // const tokenResult = await oauth.processAuthorizationCodeResponse(authorizationServer, clientRegistration, tokenResponse, {expectedNonce: nonce})
        const tokenResult = await oauth.processAuthorizationCodeResponse(authorizationServer, clientRegistration, tokenResponse)

        const headers = new Headers(request.headers)

        // @ts-expect-error internal API
        await dpop.addProof(new URL(request.url), headers, request.method, tokenResult.access_token) // TODO: Don't use internal API
        headers.set("Authorization", ["DPoP", tokenResult.access_token].join(" "))

        return new Request(request, {headers})
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

function authenticationMethodFor(issuer: string): (clientSecret: string) => oauth.ClientAuth {
    // TODO: Better fingerprinting ESS
    if (issuer.includes("login.inrupt.com")) {
        console.debug("Using token authentication workaround for ESS")
        return NoUrlEncodeClientSecretBasic
    }

    // TODO: Should choose based on client/issuer metadata regardles of ESS
    return oauth.ClientSecretBasic
}
