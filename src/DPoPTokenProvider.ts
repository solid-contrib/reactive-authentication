import * as oauth from "oauth4webapi"
import * as DPoP from "dpop"
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

        const discoveryResponse = await oauth.discoveryRequest(issuer)
        const authorizationServer = await oauth.processDiscoveryResponse(issuer, discoveryResponse)

        const callbackUri = await this.#getCallback(request)

        const registrationResponse = await oauth.dynamicClientRegistrationRequest(authorizationServer, {redirect_uris: [callbackUri]})
        const clientRegistration = await oauth.processDynamicClientRegistrationResponse(registrationResponse)
        const [registeredRedirectUri] = clientRegistration.redirect_uris as string[]
        const [registeredResponseType] = clientRegistration.response_types as string[]

        const dpopKey = await oauth.generateKeyPair("ES256", {extractable: false}) // TODO: Align with dpop_signing_alg_values_supported and fallback
        const dpop = oauth.DPoP({}, dpopKey)

        const codeVerifier = oauth.generateRandomCodeVerifier()
        const nonce = oauth.generateRandomNonce()
        const state = oauth.generateRandomState()

        const authorizationUrl = new URL(authorizationServer.authorization_endpoint!)
        authorizationUrl.searchParams.set("client_id", clientRegistration.client_id)
        authorizationUrl.searchParams.set("redirect_uri", registeredRedirectUri!)
        authorizationUrl.searchParams.set("response_type", registeredResponseType!)
        authorizationUrl.searchParams.set("scope", "openid webid")
        authorizationUrl.searchParams.set("prompt", "none")
        authorizationUrl.searchParams.set("state", state)
        authorizationUrl.searchParams.set("nonce", nonce)

        if (authorizationServer.code_challenge_methods_supported !== undefined) {
            if (authorizationServer.code_challenge_methods_supported.includes("S256")) {
                authorizationUrl.searchParams.set("code_challenge_method", "S256")
                authorizationUrl.searchParams.set("code_challenge", await oauth.calculatePKCECodeChallenge(codeVerifier))
            } else {
                authorizationUrl.searchParams.set("code_challenge_method", "plain")
                authorizationUrl.searchParams.set("code_challenge", codeVerifier)
            }
        }

        const authorizationCodeResponse = await this.#getCode(authorizationUrl, request.signal)

        let authorizationCodeParams
        try {
            authorizationCodeParams = oauth.validateAuthResponse(authorizationServer, clientRegistration, new URL(authorizationCodeResponse), state)
        } catch (e) {
            if (
                // Proper way
                e instanceof oauth.AuthorizationResponseError && (e.error === "interaction_required" || e.error === "consent_required" || e.error === "login_required") ||

                // Workaround ESS not returning `iss` in error response
                isEssMissingIssInteractionNeeded(e)
            ) {
                console.debug("Authorization server requires user interaction, retrying without prompt")

                authorizationUrl.searchParams.delete("prompt")
                const authorizationCodeResponse = await this.#getCode(authorizationUrl, request.signal)
                authorizationCodeParams = oauth.validateAuthResponse(authorizationServer, clientRegistration, new URL(authorizationCodeResponse), state)
            } else {
                throw e
            }
        }

        const tokenResponse = await oauth.authorizationCodeGrantRequest(authorizationServer, clientRegistration, this.getClientAuth(authorizationServer.issuer, clientRegistration), authorizationCodeParams, callbackUri, authorizationServer.code_challenge_methods_supported !== undefined ? codeVerifier : oauth.nopkce, {DPoP: dpop})

        const tokenResult = await oauth.processAuthorizationCodeResponse(authorizationServer, clientRegistration, tokenResponse, {expectedNonce: this.nonceVerificationOverride(authorizationServer.issuer, nonce)})

        const headers = new Headers(request.headers)

        headers.set("DPoP", await DPoP.generateProof(dpopKey, request.url, request.method, undefined, tokenResult.access_token))
        headers.set("Authorization", ["DPoP", tokenResult.access_token].join(" "))

        return new Request(request, {headers})
    }

    private getClientAuth(issuer: string, client: oauth.OmitSymbolProperties<oauth.Client>): oauth.ClientAuth {
        const clientSecret = client.client_secret as string

        if (client.token_endpoint_auth_method === "client_secret_basic") {
            const clientSecretBasic = clientSecretBasicFor(issuer)
            return clientSecretBasic(clientSecret)
        }

        return oauth.None()
    }

    private nonceVerificationOverride(issuer: string, nonce: string): string | typeof oauth.expectNoNonce {
        // TODO: Expose or configure or fingerprint NSS
        if (issuer === "https://datapod.igrant.io" || issuer === "https://solidweb.org") {
            return oauth.expectNoNonce
        }

        return nonce
    }
}

function isEssMissingIssInteractionNeeded(e: unknown) {
    try {
        return ((((e as oauth.OperationProcessingError).cause as any).parameters) as URLSearchParams).get("error") === "interaction_required"
    } catch {
        return false
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
