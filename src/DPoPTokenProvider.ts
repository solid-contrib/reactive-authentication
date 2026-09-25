import type { Cache } from "./Cache.js"
import { MemoryCache } from "./MemoryCache.js"
import * as oauth from "oauth4webapi"
import * as DPoP from "dpop"
import type { CodeProvider } from "./CodeProvider.js"
import type { TokenProvider } from "./TokenProvider.js"
import type { AuthorizationServerProvider } from "./AuthorizationServerProvider.js"
import { ClientProvider } from "./ClientProvider.js"
import { supportsOfflineAccess } from "./supportsOfflineAccess.js"

/** Sensitive, structured-cloneable credential record. Never JSON-serialize its keys. */
export type DPoPTokenCacheEntry = {
    created: number,
    tokenResult: oauth.TokenEndpointResponse,
    dpopKey: CryptoKeyPair,
    client: oauth.Client,
    authorizationServer: oauth.AuthorizationServer,
}

export class DPoPTokenProvider implements TokenProvider {
    readonly #codeProvider: CodeProvider
    readonly #callbackUri: string

    // A cache must be isolated per application, client configuration and account.
    readonly #cache: Cache<DPoPTokenCacheEntry>
    readonly #asProvider: AuthorizationServerProvider
    readonly #clientProvider: ClientProvider

    constructor(callbackUri: string, codeProvider: CodeProvider, asProvider: AuthorizationServerProvider, clientProvider: ClientProvider, cache: Cache<DPoPTokenCacheEntry> = new MemoryCache()) {
        this.#cache = cache
        this.#codeProvider = codeProvider
        this.#callbackUri = callbackUri
        this.#asProvider = asProvider
        this.#clientProvider = clientProvider
    }

    async matches(request: Request): Promise<boolean> {
        return true
    }

    async upgrade(request: Request): Promise<Request> {
        // Form a queue per request URI to never reuse refresh tokens.
        // TODO: Revise scope (origin+requestUri) of this lock which might interfere with scenarios that are not bound to origin
        const lockName = `DPoPTokenProvider.upgrade[${request.url}]`
        const {dpopKey, tokenResult: {access_token}} = await navigator.locks.request(lockName, async _ =>
            await this.getCachedToken(request))

        const headers = new Headers(request.headers)

        headers.set("DPoP", await DPoP.generateProof(dpopKey, request.url, request.method, undefined, access_token))
        headers.set("Authorization", ["DPoP", access_token].join(" "))

        return new Request(request, {headers})
    }

    private async getCachedToken(request: Request): Promise<DPoPTokenCacheEntry> {
        // TODO: More robust key via callback to support complex caching scenarios
        const cached = await this.#cache.get(request.url)

        // TODO: Support actively refreshing the token
        if (cached !== undefined) {
            if (!isExpired(cached)) {
                return cached
            }

            const refreshed = await this.refreshToken(cached, request)
            if (refreshed !== undefined) {
                await this.#cache.set(request.url, refreshed)
                return refreshed
            }
        }

        const fresh = await this.obtainToken(request)
        await this.#cache.set(request.url, fresh)

        return fresh
    }

    private async obtainToken(request: Request): Promise<DPoPTokenCacheEntry> {
        const authorizationServer = await this.#asProvider.getAuthorizationServer(request)

        const clientRegistration = await this.#clientProvider.getClient(authorizationServer, this.#callbackUri, request.signal)
        const [registeredRedirectUri] = clientRegistration.redirect_uris as string[]
        const [registeredResponseType] = clientRegistration.response_types as string[]

        const dpopKey = await oauth.generateKeyPair("ES256", {extractable: false}) // TODO: Align with dpop_signing_alg_values_supported and fallback
        const dpop = oauth.DPoP({}, dpopKey)

        const codeVerifier = oauth.generateRandomCodeVerifier()
        const nonce = oauth.generateRandomNonce()
        const state = oauth.generateRandomState()

        const scopes = ["openid", "webid"]
        if (supportsOfflineAccess(authorizationServer)) {
            scopes.push("offline_access")
        }

        const authorizationUrl = new URL(authorizationServer.authorization_endpoint!)
        authorizationUrl.searchParams.set("client_id", clientRegistration.client_id)
        authorizationUrl.searchParams.set("redirect_uri", registeredRedirectUri!)
        authorizationUrl.searchParams.set("response_type", registeredResponseType!)
        authorizationUrl.searchParams.set("scope", scopes.join(" "))
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

        using authorizationCodeResponse = await this.#codeProvider.getCode(authorizationUrl, request.signal)

        let authorizationCodeParams
        try {
            authorizationCodeParams = oauth.validateAuthResponse(authorizationServer, clientRegistration, new URL(authorizationCodeResponse.value), state)
        } catch (e) {
            if (
                // Proper way
                e instanceof oauth.AuthorizationResponseError && (e.error === "interaction_required" || e.error === "consent_required" || e.error === "login_required") ||

                // Workaround ESS not returning `iss` in error response
                // TODO: Eliminate once bug fixed
                isEssMissingIssInteractionNeeded(e)
            ) {
                console.debug("Authorization server requires user interaction, retrying without prompt")

                authorizationUrl.searchParams.delete("prompt")
                using authorizationCodeResponse = await this.#codeProvider.getCode(authorizationUrl, request.signal)
                authorizationCodeParams = oauth.validateAuthResponse(authorizationServer, clientRegistration, new URL(authorizationCodeResponse.value), state)
            } else {
                throw e
            }
        }

        const tokenResponse = await oauth.authorizationCodeGrantRequest(authorizationServer, clientRegistration, this.getClientAuth(authorizationServer.issuer, clientRegistration), authorizationCodeParams, this.#callbackUri, authorizationServer.code_challenge_methods_supported !== undefined ? codeVerifier : oauth.nopkce, {DPoP: dpop, signal: request.signal})

        const tokenResult = await oauth.processAuthorizationCodeResponse(authorizationServer, clientRegistration, tokenResponse, {expectedNonce: this.nonceVerificationOverride(authorizationServer.issuer, nonce)})

        return {created: Date.now(), tokenResult, dpopKey, client: clientRegistration, authorizationServer}
    }

    private async refreshToken(cached: DPoPTokenCacheEntry, request: Request): Promise<DPoPTokenCacheEntry | undefined> {
        if (cached.tokenResult.refresh_token === undefined) {
            return undefined
        }

        // Remove before consuming a potentially rotating token. A failed grant/write
        // must not leave a consumed refresh token available to another tab.
        await this.#cache.delete(request.url)

        const dpop = oauth.DPoP({}, cached.dpopKey)
        const options = {DPoP: dpop}

        let tokenResult: oauth.TokenEndpointResponse
        try {
            const tokenResponse = await oauth.refreshTokenGrantRequest(cached.authorizationServer, cached.client, this.getClientAuth(cached.authorizationServer.issuer, cached.client), cached.tokenResult.refresh_token, options)
            tokenResult = await oauth.processRefreshTokenResponse(cached.authorizationServer, cached.client, tokenResponse)
        } catch (e) {
            if (e instanceof oauth.ResponseBodyError && e.error === "invalid_grant") {
                console.debug("Access token could not be refreshed")

                return undefined
            }

            throw e
        }

        // Reuse cached refreshed token if it wasn't rotated (token result didn't have one)
        if (tokenResult.refresh_token === undefined) {
            // Leave rest of token result intact
            tokenResult = {...tokenResult, refresh_token: cached.tokenResult.refresh_token}
        }

        return {created: Date.now(), tokenResult, dpopKey: cached.dpopKey, client: cached.client, authorizationServer: cached.authorizationServer}
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

/**
 * @see Bug report at https://inrupt.atlassian.net/servicedesk/customer/portal/4/FEEDBACK-445
 * @see Bug repro at https://gist.github.com/langsamu/ac55045a6ddc5893000b722429146b3a#file-iss_missing_error_callback-html
 * @see Spec https://www.rfc-editor.org/rfc/rfc9207.html#name-response-parameter-iss
 */
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
 * @see Bug report at https://inrupt.atlassian.net/servicedesk/customer/portal/4/FEEDBACK-443
 * @see Bug repro at https://gist.github.com/langsamu/ac55045a6ddc5893000b722429146b3a#file-podspaces_client_auth_bug-html
 * @see Spec https://www.rfc-editor.org/rfc/rfc6749.html#section-2.3.1
 */
function NoUrlEncodeClientSecretBasic(clientSecret: string): oauth.ClientAuth {
    return function (_, client, __, headers) {
        console.debug("Using non-conforming (no url encoding) client secret basic token authentication")
        headers.set("Authorization", `Basic ${btoa(`${client.client_id}:${clientSecret}`)}`);
    };
}

// TODO: Eliminate once bug fixed
function clientSecretBasicFor(issuer: string): (clientSecret: string) => oauth.ClientAuth {
    // TODO: Better fingerprinting ESS
    if (issuer.includes("login.inrupt.com")) {
        console.debug("Using token authentication workaround for ESS")
        return NoUrlEncodeClientSecretBasic
    }

    return oauth.ClientSecretBasic
}

function isExpired(tokenData: DPoPTokenCacheEntry) {
    // TODO: Add some headroom (expire a bit before limit)
    // TODO: What to do when `expires_in` is Missing? (optional in https://datatracker.ietf.org/doc/html/rfc6749#section-4.2.2)
    return Date.now() - tokenData.created > tokenData.tokenResult.expires_in! * 1_000;
}
