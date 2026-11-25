import assert from "node:assert/strict"
import {describe, it} from "node:test"
import * as oauth from "oauth4webapi"
import type {AuthorizationServerProvider} from "../src/AuthorizationServerProvider.js"
import type {ClientProvider} from "../src/ClientProvider.js"
import type {CodeProvider} from "../src/CodeProvider.js"
import type {IssuerProvider} from "../src/IssuerProvider.js"
import {IdTokenSubjectTokenProvider, idTokenType} from "../src/IdTokenSubjectTokenProvider.js"

const client: oauth.Client = {
    client_id: "client",
    redirect_uris: ["https://app.example/callback"],
    response_types: ["code"],
    token_endpoint_auth_method: "none",
}

const base64Url = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url")

const now = () => Math.floor(Date.now() / 1000)

let counter = 0

const idToken = (issuer: string, exp: number, nonce?: string) =>
    [
        base64Url({alg: "RS256"}),
        base64Url({iss: issuer, sub: "subject", aud: client.client_id, exp, iat: exp - 60, jti: String(++counter), ...(nonce && {nonce})}),
        "signature",
    ].join(".")

type Behavior = {
    exp?: number,
    refreshExp?: number,
    refreshToken?: string | undefined,
    refreshIdToken?: boolean,
    refreshError?: string,
    dpopAlgs?: string[],
}

function setup(behavior: Behavior = {}) {
    const authorizationUrls: URL[] = []
    const tokenRequests: {body: URLSearchParams, headers: Headers}[] = []

    const metadata = (issuer: URL): oauth.AuthorizationServer => ({
        issuer: issuer.href,
        authorization_endpoint: new URL("authorize", issuer).href,
        token_endpoint: new URL("token", issuer).href,
        code_challenge_methods_supported: ["S256"],
        ...(behavior.dpopAlgs && {dpop_signing_alg_values_supported: behavior.dpopAlgs}),
    })

    const codeProvider: CodeProvider = {
        async getCode(authorizationUri) {
            authorizationUrls.push(new URL(authorizationUri))

            return {value: `https://app.example/callback?code=the-code&state=${authorizationUri.searchParams.get("state")}`, [Symbol.dispose]() {}}
        },
    }

    const options = {
        [oauth.customFetch]: async (url: string, init: oauth.CustomFetchOptions<any, any>) => {
            const issuer = new URL("./", url).href
            const body = new URLSearchParams(init.body as string)
            tokenRequests.push({body, headers: new Headers(init.headers as HeadersInit)})

            if (body.get("grant_type") === "refresh_token") {
                if (behavior.refreshError !== undefined) {
                    return Response.json({error: behavior.refreshError}, {status: 400})
                }

                return Response.json({
                    access_token: "access",
                    token_type: "Bearer",
                    ...(behavior.refreshIdToken !== false && {id_token: idToken(issuer, behavior.refreshExp ?? now() + 3600)}),
                    ...(behavior.refreshToken !== undefined && {refresh_token: behavior.refreshToken}),
                })
            }

            const nonce = authorizationUrls.at(-1)!.searchParams.get("nonce")!

            return Response.json({
                access_token: "access",
                token_type: "Bearer",
                id_token: idToken(issuer, behavior.exp ?? now() + 3600, nonce),
                refresh_token: "refresh",
            })
        },
    }

    let issuer = new URL("https://issuer.example")
    const issuerProvider: IssuerProvider = {
        async getIssuer() {
            return issuer
        },
    }
    const asProvider: AuthorizationServerProvider = {
        async getAuthorizationServer(i) {
            return metadata(i)
        },
    }
    const clientProvider: ClientProvider = {
        async getClient() {
            return client
        },
    }

    const provider = new IdTokenSubjectTokenProvider("https://app.example/callback", codeProvider, issuerProvider, asProvider, clientProvider, options)

    return {provider, authorizationUrls, tokenRequests, useIssuer(i: string) { issuer = new URL(i) }}
}

const request = new Request("https://storage.example/resource")
const signal = new AbortController().signal

describe("IdTokenSubjectTokenProvider", () => {
    it("returns the ID token with the ID token type", async () => {
        const s = setup()

        const subjectToken = await s.provider.getSubjectToken(request, signal)

        assert.equal(subjectToken.type, idTokenType)
        assert.equal(subjectToken.type, "urn:ietf:params:oauth:token-type:id_token")
        assert.equal(subjectToken.token.split(".").length, 3)
        assert.equal(s.authorizationUrls[0]!.searchParams.get("scope"), "openid webid offline_access")
    })

    it("reuses the subjectToken for the same issuer", async () => {
        const s = setup()

        const first = await s.provider.getSubjectToken(request, signal)
        const second = await s.provider.getSubjectToken(request, signal)

        assert.equal(second.token, first.token)
        assert.equal(s.authorizationUrls.length, 1)
    })

    it("keeps subject tokens of different issuers apart", async () => {
        const s = setup()

        const first = await s.provider.getSubjectToken(request, signal)
        s.useIssuer("https://other.example")
        const second = await s.provider.getSubjectToken(request, signal)

        assert.notEqual(second.token, first.token)
        assert.equal(s.authorizationUrls.length, 2)
    })

    it("refreshes an expired ID token", async () => {
        const s = setup({exp: now() + 10})

        const first = await s.provider.getSubjectToken(request, signal)
        const second = await s.provider.getSubjectToken(request, signal)

        assert.notEqual(second.token, first.token)
        assert.equal(s.authorizationUrls.length, 1)
        assert.equal(s.tokenRequests.at(-1)!.body.get("grant_type"), "refresh_token")
        assert.equal(s.tokenRequests.at(-1)!.body.get("refresh_token"), "refresh")
    })

    it("runs the grant again when the refresh response has no ID token", async () => {
        const s = setup({exp: now() + 10, refreshIdToken: false})

        await s.provider.getSubjectToken(request, signal)
        await s.provider.getSubjectToken(request, signal)

        assert.equal(s.authorizationUrls.length, 2)
    })

    it("runs the grant again when the refresh token is rejected", async () => {
        const s = setup({exp: now() + 10, refreshError: "invalid_grant"})

        await s.provider.getSubjectToken(request, signal)
        const second = await s.provider.getSubjectToken(request, signal)

        assert.equal(s.authorizationUrls.length, 2)
        assert.equal(second.type, idTokenType)
    })

    it("runs the grant again after the subjectToken is invalidated", async () => {
        const s = setup()

        const first = await s.provider.getSubjectToken(request, signal)
        await s.provider.invalidate(request, first)
        const second = await s.provider.getSubjectToken(request, signal)

        assert.notEqual(second.token, first.token)
        assert.equal(s.authorizationUrls.length, 2)
    })

    it("ignores the invalidation of a subjectToken that was already replaced", async () => {
        const s = setup()

        const first = await s.provider.getSubjectToken(request, signal)
        await s.provider.invalidate(request, {token: "something else", type: idTokenType})
        const second = await s.provider.getSubjectToken(request, signal)

        assert.equal(second.token, first.token)
        assert.equal(s.authorizationUrls.length, 1)
    })

    it("sends DPoP when the authorization server advertises algorithms", async () => {
        const s = setup({dpopAlgs: ["ES256"]})

        await s.provider.getSubjectToken(request, signal)

        assert.ok(s.tokenRequests[0]!.headers.get("DPoP"))
    })

    it("returns the DPoP key that the ID token is bound to", async () => {
        const s = setup({dpopAlgs: ["ES256"]})

        const subjectToken = await s.provider.getSubjectToken(request, signal)

        const proofJwk = JSON.parse(Buffer.from(s.tokenRequests[0]!.headers.get("DPoP")!.split(".")[0]!, "base64url").toString()).jwk
        const keyJwk = await crypto.subtle.exportKey("jwk", subjectToken.dpopKey!.publicKey)
        assert.equal(keyJwk.x, proofJwk.x)
        assert.equal(keyJwk.y, proofJwk.y)
    })

    it("returns no DPoP key without DPoP", async () => {
        const s = setup()

        const subjectToken = await s.provider.getSubjectToken(request, signal)

        assert.equal(subjectToken.dpopKey, undefined)
    })

    it("reuses the DPoP key to refresh", async () => {
        const s = setup({dpopAlgs: ["ES256"], exp: now() + 10})

        await s.provider.getSubjectToken(request, signal)
        await s.provider.getSubjectToken(request, signal)

        const [grant, refresh] = s.tokenRequests.map(r => JSON.parse(Buffer.from(r.headers.get("DPoP")!.split(".")[0]!, "base64url").toString()).jwk)
        assert.deepEqual(refresh, grant)
    })

    it("does not send DPoP otherwise", async () => {
        const s = setup()

        await s.provider.getSubjectToken(request, signal)

        assert.equal(s.tokenRequests[0]!.headers.has("DPoP"), false)
    })
})
