import * as oauth from "oauth4webapi"
import type { CodeProvider } from "./CodeProvider.js"
import { supportsOfflineAccess } from "./supportsOfflineAccess.js"
import { withDPoPNonceRetry } from "./dpopNonce.js"

export type AuthorizationCodeGrantParameters = {
    authorizationServer: oauth.AuthorizationServer,
    client: oauth.Client,
    callbackUri: string,
    codeProvider: CodeProvider,
    dpop?: oauth.DPoPHandle,
    scopes: string[],
    options?: oauth.HttpRequestOptions<string, any> | undefined,
    signal: AbortSignal,
}

export type RefreshGrantParameters = {
    authorizationServer: oauth.AuthorizationServer,
    client: oauth.Client,
    refreshToken: string,
    dpop?: oauth.DPoPHandle,
    options?: oauth.HttpRequestOptions<string, any> | undefined,
}

/**
 * Runs the OAuth authorization code grant with PKCE and a nonce: first without user interaction (`prompt=none`), then
 * interactively if the authorization server demands it. Adds `offline_access` to `scopes` if the server supports it.
 * The returned response carries the `id_token` when the server issued one.
 *
 * @internal
 */
export async function runAuthorizationCodeGrant({authorizationServer, client, callbackUri, codeProvider, dpop, scopes, options, signal}: AuthorizationCodeGrantParameters): Promise<oauth.TokenEndpointResponse> {
    const [registeredRedirectUri] = client.redirect_uris as string[]
    const [registeredResponseType] = client.response_types as string[]

    const codeVerifier = oauth.generateRandomCodeVerifier()
    const nonce = oauth.generateRandomNonce()
    const state = oauth.generateRandomState()

    scopes = [...scopes]
    if (supportsOfflineAccess(authorizationServer)) {
        scopes.push("offline_access")
    }

    const authorizationUrl = new URL(authorizationServer.authorization_endpoint!)
    authorizationUrl.searchParams.set("client_id", client.client_id)
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

    using authorizationCodeResponse = await codeProvider.getCode(authorizationUrl, signal)

    let authorizationCodeParams
    try {
        authorizationCodeParams = oauth.validateAuthResponse(authorizationServer, client, new URL(authorizationCodeResponse.value), state)
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
            using authorizationCodeResponse = await codeProvider.getCode(authorizationUrl, signal)
            authorizationCodeParams = oauth.validateAuthResponse(authorizationServer, client, new URL(authorizationCodeResponse.value), state)
        } else {
            throw e
        }
    }

    return await withDPoPNonceRetry(async () => {
        const tokenResponse = await oauth.authorizationCodeGrantRequest(authorizationServer, client, getClientAuth(authorizationServer.issuer, client), authorizationCodeParams, callbackUri, authorizationServer.code_challenge_methods_supported !== undefined ? codeVerifier : oauth.nopkce, {...options, ...(dpop && {DPoP: dpop}), signal})

        return await oauth.processAuthorizationCodeResponse(authorizationServer, client, tokenResponse, {expectedNonce: nonceVerificationOverride(authorizationServer.issuer, nonce)})
    })
}

/**
 * @internal
 */
export async function refreshGrant({authorizationServer, client, refreshToken, dpop, options}: RefreshGrantParameters): Promise<oauth.TokenEndpointResponse> {
    const requestOptions = {...options, ...(dpop && {DPoP: dpop})}

    return await withDPoPNonceRetry(async () => {
        const tokenResponse = await oauth.refreshTokenGrantRequest(authorizationServer, client, getClientAuth(authorizationServer.issuer, client), refreshToken, requestOptions)

        return await oauth.processRefreshTokenResponse(authorizationServer, client, tokenResponse)
    })
}

function getClientAuth(issuer: string, client: oauth.OmitSymbolProperties<oauth.Client>): oauth.ClientAuth {
    const clientSecret = client.client_secret as string

    if (client.token_endpoint_auth_method === "client_secret_basic") {
        const clientSecretBasic = clientSecretBasicFor(issuer)
        return clientSecretBasic(clientSecret)
    }

    return oauth.None()
}

function nonceVerificationOverride(issuer: string, nonce: string): string | typeof oauth.expectNoNonce {
    // TODO: Expose or configure or fingerprint NSS
    if (issuer === "https://datapod.igrant.io" || issuer === "https://solidweb.org") {
        return oauth.expectNoNonce
    }

    return nonce
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
