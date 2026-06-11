/**
 * A minimal in-memory OAuth 2.0 / OpenID Connect authorization server for unit
 * tests, exposed as a `fetch` implementation to stub `globalThis.fetch` with.
 *
 * It implements just enough for oauth4webapi's strict client side: discovery,
 * JWKS, dynamic client registration, and a token endpoint handling the
 * `authorization_code` and `refresh_token` grants — including ES256-signed ID
 * tokens (oauth4webapi requires a valid ID token whenever a nonce is expected)
 * and refresh-token rotation.
 */

export interface FakeAuthorizationServerOptions {
    /** `expires_in` reported on every token response. Default 3600. */
    expiresIn?: number
    /** Whether token responses include a refresh token. Default false. */
    issueRefreshTokens?: boolean
    /** Whether the refresh-token grant rotates the refresh token. Default true. */
    rotateRefreshTokens?: boolean
    /** `scopes_supported` advertised by discovery. Default ["openid", "webid"]. */
    scopesSupported?: string[]
    /** `grant_types_supported` advertised by discovery. Default ["authorization_code"]. */
    grantTypesSupported?: string[]
}

export interface AuthorizationRequestRecord {
    scope: string | null
    prompt: string | null
    clientId: string | null
}

export interface FakeAuthorizationServer {
    readonly issuer: string
    /** Stub `globalThis.fetch` with this. */
    fetch: typeof globalThis.fetch
    /**
     * The "user agent": simulates visiting the authorization endpoint and
     * returns the redirect-back URL carrying `code` and `state`. Use as the
     * provider's `getCode` callback.
     */
    authorize(authorizationUrl: URL): Promise<string>
    /** Every authorization request seen, oldest first. */
    readonly authorizationRequests: AuthorizationRequestRecord[]
    /** Client registration metadata bodies received, oldest first. */
    readonly registrations: Record<string, unknown>[]
    /** Form bodies received by the token endpoint, oldest first. */
    readonly tokenRequests: URLSearchParams[]
    /** Refresh tokens that are currently redeemable. */
    readonly activeRefreshTokens: Set<string>
}

const encoder = new TextEncoder()

function base64url(data: Uint8Array | string): string {
    const bytes = typeof data === "string" ? encoder.encode(data) : data
    let binary = ""
    for (const b of bytes) binary += String.fromCharCode(b)
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
}

function json(body: unknown, status = 200): Response {
    return new Response(JSON.stringify(body), {status, headers: {"content-type": "application/json"}})
}

export async function createFakeAuthorizationServer(options: FakeAuthorizationServerOptions = {}): Promise<FakeAuthorizationServer> {
    const issuer = "https://as.test"
    const expiresIn = options.expiresIn ?? 3600
    const rotate = options.rotateRefreshTokens ?? true

    const keys = await crypto.subtle.generateKey({name: "ECDSA", namedCurve: "P-256"}, true, ["sign", "verify"]) as CryptoKeyPair
    const publicJwk = await crypto.subtle.exportKey("jwk", keys.publicKey)

    let counter = 0
    /** nonce + client of each outstanding authorization code */
    const codes = new Map<string, {nonce: string | null, clientId: string | null}>()
    const activeRefreshTokens = new Set<string>()
    const authorizationRequests: AuthorizationRequestRecord[] = []
    const registrations: Record<string, unknown>[] = []
    const tokenRequests: URLSearchParams[] = []

    async function signIdToken(clientId: string, nonce: string | null): Promise<string> {
        const header = base64url(JSON.stringify({alg: "ES256", kid: "test"}))
        const now = Math.floor(Date.now() / 1000)
        const claims: Record<string, unknown> = {iss: issuer, sub: "user", aud: clientId, iat: now, exp: now + 600}
        if (nonce !== null) claims.nonce = nonce
        const payload = base64url(JSON.stringify(claims))
        const signature = await crypto.subtle.sign({name: "ECDSA", hash: "SHA-256"}, keys.privateKey, encoder.encode(`${header}.${payload}`))
        return `${header}.${payload}.${base64url(new Uint8Array(signature))}`
    }

    function tokenBody(refreshable: boolean, idToken?: string) {
        const body: Record<string, unknown> = {
            access_token: `at-${++counter}`,
            token_type: "DPoP",
            expires_in: expiresIn,
            scope: "openid webid",
        }
        if (idToken !== undefined) body.id_token = idToken
        if (refreshable) {
            const refreshToken = `rt-${counter}`
            activeRefreshTokens.add(refreshToken)
            body.refresh_token = refreshToken
        }
        return body
    }

    async function handle(request: Request): Promise<Response> {
        const url = new URL(request.url)

        if (url.href === `${issuer}/.well-known/openid-configuration`) {
            return json({
                issuer,
                authorization_endpoint: `${issuer}/authorize`,
                token_endpoint: `${issuer}/token`,
                registration_endpoint: `${issuer}/register`,
                jwks_uri: `${issuer}/jwks`,
                code_challenge_methods_supported: ["S256"],
                id_token_signing_alg_values_supported: ["ES256"],
                scopes_supported: options.scopesSupported ?? ["openid", "webid"],
                grant_types_supported: options.grantTypesSupported ?? ["authorization_code"],
            })
        }

        if (url.pathname === "/jwks") {
            return json({keys: [{...publicJwk, alg: "ES256", use: "sig", kid: "test"}]})
        }

        if (url.pathname === "/register") {
            const metadata = await request.json() as Record<string, unknown>
            registrations.push(metadata)
            return json({
                client_id: `client-${++counter}`,
                redirect_uris: metadata.redirect_uris,
                response_types: ["code"],
                grant_types: metadata.grant_types ?? ["authorization_code"],
                token_endpoint_auth_method: "none",
            }, 201)
        }

        if (url.pathname === "/token") {
            const params = new URLSearchParams(await request.text())
            tokenRequests.push(params)

            if (params.get("grant_type") === "authorization_code") {
                const code = codes.get(params.get("code") ?? "")
                if (code === undefined) {
                    return json({error: "invalid_grant"}, 400)
                }
                codes.delete(params.get("code")!)
                return json(tokenBody(options.issueRefreshTokens ?? false, await signIdToken(params.get("client_id") ?? code.clientId ?? "", code.nonce)))
            }

            if (params.get("grant_type") === "refresh_token") {
                const presented = params.get("refresh_token") ?? ""
                if (!activeRefreshTokens.has(presented)) {
                    return json({error: "invalid_grant"}, 400)
                }
                if (rotate) {
                    activeRefreshTokens.delete(presented)
                }
                return json(tokenBody(true))
            }

            return json({error: "unsupported_grant_type"}, 400)
        }

        return new Response("not found", {status: 404})
    }

    return {
        issuer,
        fetch: (input, init) => handle(new Request(input, init)),
        async authorize(authorizationUrl: URL): Promise<string> {
            authorizationRequests.push({
                scope: authorizationUrl.searchParams.get("scope"),
                prompt: authorizationUrl.searchParams.get("prompt"),
                clientId: authorizationUrl.searchParams.get("client_id"),
            })
            const code = `code-${++counter}`
            codes.set(code, {
                nonce: authorizationUrl.searchParams.get("nonce"),
                clientId: authorizationUrl.searchParams.get("client_id"),
            })
            const redirect = new URL(authorizationUrl.searchParams.get("redirect_uri")!)
            redirect.searchParams.set("code", code)
            redirect.searchParams.set("state", authorizationUrl.searchParams.get("state")!)
            return redirect.href
        },
        authorizationRequests,
        registrations,
        tokenRequests,
        activeRefreshTokens,
    }
}
