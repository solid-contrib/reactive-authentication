import * as oauth from "oauth4webapi"
import * as DPoP from "dpop"
import type { GetCodeCallback } from "./GetCodeCallback.js"
import type { TokenProvider } from "./TokenProvider.js"
import type { AuthorizationServerProvider } from "./AuthorizationServerProvider.js"

type CacheEntry = { created: number, tokenResult: oauth.TokenEndpointResponse, dpopKey: CryptoKeyPair }

export class DPoPTokenProvider implements TokenProvider {
    readonly #getCode: GetCodeCallback
    readonly #callbackUri: string
    readonly #cache = new Map<string, CacheEntry> // TODO: Take cache from caller
    readonly #asProvider: AuthorizationServerProvider

    constructor(callbackUri: string, getCodeCallback: GetCodeCallback, asProvider: AuthorizationServerProvider) {
        this.#getCode = getCodeCallback
        this.#callbackUri = callbackUri
        this.#asProvider = asProvider
    }

    async matches(request: Request): Promise<boolean> {
        return true
    }

    async upgrade(request: Request): Promise<Request> {
        // TODO: More robust key via callback to support complex caching scenarios
        let tokenData = this.#cache.get(request.url)
        // TODO: Support actively refreshing the token
        if (tokenData === undefined || isExpired(tokenData)) {
            tokenData = await this.obtainToken(request)
            this.#cache.set(request.url, tokenData)
        }

        const headers = new Headers(request.headers)

        headers.set("DPoP", await DPoP.generateProof(tokenData.dpopKey, request.url, request.method, undefined, tokenData.tokenResult.access_token))
        headers.set("Authorization", ["DPoP", tokenData.tokenResult.access_token].join(" "))
        return new Request(request, {headers})
    }
    private async obtainToken(request: Request): Promise<CacheEntry> {
        const authorizationServer = await this.#asProvider.getAuthorizationServer(request)

        const registrationResponse = await oauth.dynamicClientRegistrationRequest(authorizationServer, {redirect_uris: [this.#callbackUri]}, {signal: request.signal})
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

        const tokenResponse = await oauth.authorizationCodeGrantRequest(authorizationServer, clientRegistration, this.getClientAuth(authorizationServer.issuer, clientRegistration), authorizationCodeParams, this.#callbackUri, authorizationServer.code_challenge_methods_supported !== undefined ? codeVerifier : oauth.nopkce, {DPoP: dpop, signal: request.signal})

        const tokenResult = await oauth.processAuthorizationCodeResponse(authorizationServer, clientRegistration, tokenResponse, {expectedNonce: this.nonceVerificationOverride(authorizationServer.issuer, nonce)})

        return {created: Date.now(), tokenResult, dpopKey}
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

function isExpired(tokenData: CacheEntry) {
    // TODO: Add some headroom (expire a bit before limit)
    // TODO: What to do when `expires_in` is Missing? (optional in https://datatracker.ietf.org/doc/html/rfc6749#section-4.2.2)
    return Date.now() - tokenData.created > tokenData.tokenResult.expires_in! * 1_000;
}
