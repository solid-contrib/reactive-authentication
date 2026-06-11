import * as oauth from "oauth4webapi"
import * as DPoP from "dpop"
import type { GetCodeCallback } from "./GetCodeCallback.js"
import type { TokenProvider } from "./TokenProvider.js"
import type { GetIssuerCallback } from "./GetIssuerCallback.js"

/** The client metadata shape produced by dynamic client registration. */
type ClientRegistration = Awaited<ReturnType<typeof oauth.processDynamicClientRegistrationResponse>>

/** Authentication state for one issuer, reused across upgrades. */
interface IssuerSession {
    authorizationServer: oauth.AuthorizationServer
    clientRegistration: ClientRegistration
    dpopKey: CryptoKeyPair
    /** The oauth4webapi DPoP handle for token-endpoint requests. Reused so refreshed tokens stay bound to the same key (RFC 9449 §4.3) and server-provided nonces are remembered. */
    dpopHandle: oauth.DPoPHandle
    accessToken: string
    /** The refresh token (RFC 6749 §6), when the server issued one. Updated in place when the server rotates it. */
    refreshToken: string | undefined
    /** Epoch milliseconds after which the access token is considered expired, or undefined when the server gave no expiry. */
    expiresAt: number | undefined
}

/**
 * Refresh this much before the server-reported expiry, so clock skew between us
 * and the resource server does not produce a window of rejected requests.
 */
const expirySkewMs = 30_000

export class DPoPTokenProvider implements TokenProvider {
    readonly #getCode: GetCodeCallback
    readonly #callbackUri: string
    readonly #getIssuer: GetIssuerCallback

    /**
     * Single-flight session cache per issuer: concurrent upgrades share one
     * authorization-code flow (one popup), and later upgrades reuse the
     * established token until it expires instead of re-running the flow.
     */
    readonly #sessions = new Map<string, Promise<IssuerSession>>()

    /**
     * The shared authentication work is provider-owned, so it is deliberately
     * not tied to any single request's AbortSignal — aborting one request must
     * not cancel the login that other concurrent upgrades are waiting on.
     */
    readonly #authSignal = new AbortController().signal

    constructor(callbackUri: string, getCodeCallback: GetCodeCallback, getIssuerCallback: GetIssuerCallback) {
        this.#getCode = getCodeCallback
        this.#callbackUri = callbackUri
        this.#getIssuer = getIssuerCallback
    }

    async matches(request: Request): Promise<boolean> {
        return true
    }

    async upgrade(request: Request): Promise<Request> {
        const issuer = await this.#getIssuer(request)
        const session = await this.#session(issuer)

        const headers = new Headers(request.headers)

        headers.set("DPoP", await DPoP.generateProof(session.dpopKey, request.url, request.method, undefined, session.accessToken))
        headers.set("Authorization", ["DPoP", session.accessToken].join(" "))

        return new Request(request, {headers})
    }

    /**
     * Marks the cached session stale when the access token attached to the
     * request was rejected by the resource server (still 401 after an upgrade):
     * revoked, invalidated early, or expired without a server-reported
     * lifetime. The next {@link upgrade} then renews the session — refresh
     * grant first, new authorization-code flow as fallback — instead of
     * replaying the rejected token.
     */
    async invalidate(request: Request): Promise<void> {
        const issuer = await this.#getIssuer(request)
        const pending = this.#sessions.get(issuer.href)
        if (pending === undefined) {
            return
        }

        const session = await pending.catch(() => undefined)

        // Only when the rejected token is still the cached one — a concurrent
        // renewal may already have replaced it.
        if (session !== undefined && request.headers.get("Authorization") === `DPoP ${session.accessToken}`) {
            session.expiresAt = 0
        }
    }

    /**
     * Returns the cached session for the issuer, renewing it when expired and
     * establishing it when absent. A failed flow is not cached, so the next
     * upgrade retries.
     */
    async #session(issuer: URL): Promise<IssuerSession> {
        const pending = this.#sessions.get(issuer.href)
        if (pending === undefined) {
            return this.#begin(issuer, this.#authenticate(issuer))
        }

        const session = await pending
        if (!hasExpired(session)) {
            return session
        }

        // Renew, unless a concurrent caller already replaced the expired session.
        if (this.#sessions.get(issuer.href) === pending) {
            this.#sessions.delete(issuer.href)
            return this.#begin(issuer, this.#renew(issuer, session))
        }

        return this.#session(issuer)
    }

    /** Prefers a transparent refresh-token grant; falls back to a new authorization-code flow when there is no refresh token or the grant fails (expired, revoked, rotation reuse, …). */
    async #renew(issuer: URL, expired: IssuerSession): Promise<IssuerSession> {
        if (expired.refreshToken === undefined) {
            return this.#authenticate(issuer)
        }

        try {
            return await this.#refresh(expired, expired.refreshToken)
        } catch {
            // Deliberately not logging the error: oauth4webapi errors can carry the
            // token-endpoint request/response (tokens included).
            console.debug("Refresh token grant failed, falling back to a new authorization")
            return this.#authenticate(issuer)
        }
    }

    /** The refresh-token grant (RFC 6749 §6), DPoP-bound to the session's key, adopting the rotated refresh token when the server issues one (RFC 9700 §4.14.2). */
    async #refresh(session: IssuerSession, refreshToken: string): Promise<IssuerSession> {
        const {authorizationServer, clientRegistration, dpopHandle} = session
        const clientAuth = this.getClientAuth(authorizationServer.issuer, clientRegistration)

        const grant = () => oauth.refreshTokenGrantRequest(authorizationServer, clientRegistration, clientAuth, refreshToken, {DPoP: dpopHandle, signal: this.#authSignal})

        let tokenResult
        try {
            tokenResult = await oauth.processRefreshTokenResponse(authorizationServer, clientRegistration, await grant())
        } catch (e) {
            if (!oauth.isDPoPNonceError(e)) {
                throw e
            }

            // The handle has captured the server's DPoP nonce from the error response; retry once.
            tokenResult = await oauth.processRefreshTokenResponse(authorizationServer, clientRegistration, await grant())
        }

        return {
            ...session,
            accessToken: tokenResult.access_token,
            refreshToken: tokenResult.refresh_token ?? refreshToken,
            expiresAt: expiresAt(tokenResult),
        }
    }

    /** Caches the in-flight work; evicts it on failure so the flow can be retried. */
    async #begin(issuer: URL, work: Promise<IssuerSession>): Promise<IssuerSession> {
        this.#sessions.set(issuer.href, work)
        try {
            return await work
        } catch (e) {
            if (this.#sessions.get(issuer.href) === work) {
                this.#sessions.delete(issuer.href)
            }
            throw e
        }
    }

    /** The full authorization-code flow: discovery → registration → PKCE/DPoP code grant. */
    async #authenticate(issuer: URL): Promise<IssuerSession> {
        const signal = this.#authSignal

        const discoveryResponse = await oauth.discoveryRequest(issuer, {signal})
        const authorizationServer = await oauth.processDiscoveryResponse(issuer, discoveryResponse)

        // Opt in to refresh tokens where the server supports them: register for the
        // refresh_token grant and ask for the offline_access scope (OIDC Core §11).
        // Servers that support neither see the exact requests they saw before.
        const useRefreshTokens = authorizationServer.grant_types_supported?.includes("refresh_token") ?? false
        const useOfflineAccess = authorizationServer.scopes_supported?.includes("offline_access") ?? false

        const registrationMetadata: Parameters<typeof oauth.dynamicClientRegistrationRequest>[1] = {
            redirect_uris: [this.#callbackUri],
            ...useRefreshTokens ? {grant_types: ["authorization_code", "refresh_token"]} : {},
        }

        const registrationResponse = await oauth.dynamicClientRegistrationRequest(authorizationServer, registrationMetadata, {signal})
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
        authorizationUrl.searchParams.set("scope", useOfflineAccess ? "openid webid offline_access" : "openid webid")
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

        const authorizationCodeResponse = await this.#getCode(authorizationUrl, signal)

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
                const authorizationCodeResponse = await this.#getCode(authorizationUrl, signal)
                authorizationCodeParams = oauth.validateAuthResponse(authorizationServer, clientRegistration, new URL(authorizationCodeResponse), state)
            } else {
                throw e
            }
        }

        const tokenResponse = await oauth.authorizationCodeGrantRequest(authorizationServer, clientRegistration, this.getClientAuth(authorizationServer.issuer, clientRegistration), authorizationCodeParams, this.#callbackUri, authorizationServer.code_challenge_methods_supported !== undefined ? codeVerifier : oauth.nopkce, {DPoP: dpop, signal})

        const tokenResult = await oauth.processAuthorizationCodeResponse(authorizationServer, clientRegistration, tokenResponse, {expectedNonce: this.nonceVerificationOverride(authorizationServer.issuer, nonce)})

        return {
            authorizationServer,
            clientRegistration,
            dpopKey,
            dpopHandle: dpop,
            accessToken: tokenResult.access_token,
            refreshToken: tokenResult.refresh_token,
            expiresAt: expiresAt(tokenResult),
        }
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

function expiresAt(token: oauth.TokenEndpointResponse): number | undefined {
    return token.expires_in === undefined ? undefined : Date.now() + token.expires_in * 1000 - expirySkewMs
}

function hasExpired(session: IssuerSession): boolean {
    return session.expiresAt !== undefined && Date.now() >= session.expiresAt
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
