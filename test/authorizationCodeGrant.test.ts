import assert from "node:assert/strict"
import {describe, it} from "node:test"
import * as oauth from "oauth4webapi"
import type {CodeProvider} from "../src/CodeProvider.js"
import {refreshGrant, runAuthorizationCodeGrant} from "../src/authorizationCodeGrant.js"

const authorizationServer: oauth.AuthorizationServer = {
    issuer: "https://issuer.example",
    authorization_endpoint: "https://issuer.example/authorize",
    token_endpoint: "https://issuer.example/token",
    code_challenge_methods_supported: ["S256"],
    scopes_supported: ["openid"],
}

const client: oauth.Client = {
    client_id: "client",
    redirect_uris: ["https://app.example/callback"],
    response_types: ["code"],
    token_endpoint_auth_method: "none",
}

const base64Url = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url")

const idToken = (nonce: string, exp: number) =>
    [
        base64Url({alg: "RS256"}),
        base64Url({iss: authorizationServer.issuer, sub: "subject", aud: client.client_id, exp, iat: exp - 60, nonce}),
        "signature",
    ].join(".")

function setup(callbackFor: (authorizationUrl: URL, attempt: number) => string, exp = Math.floor(Date.now() / 1000) + 3600) {
    const authorizationUrls: URL[] = []
    const tokenRequests: URLSearchParams[] = []

    const codeProvider: CodeProvider = {
        async getCode(authorizationUri) {
            authorizationUrls.push(new URL(authorizationUri))

            return {value: callbackFor(authorizationUri, authorizationUrls.length), [Symbol.dispose]() {}}
        },
    }

    const options = {
        [oauth.customFetch]: async (_: string, init: oauth.CustomFetchOptions<any, any>) => {
            tokenRequests.push(new URLSearchParams(init.body as string))
            const nonce = authorizationUrls.at(-1)!.searchParams.get("nonce")!

            return Response.json({access_token: "access", token_type: "Bearer", id_token: idToken(nonce, exp)})
        },
    }

    return {authorizationUrls, tokenRequests, codeProvider, options}
}

const success = (url: URL) => `https://app.example/callback?code=the-code&state=${url.searchParams.get("state")}`
const failure = (url: URL, error: string) => `https://app.example/callback?error=${error}&state=${url.searchParams.get("state")}`

const run = (s: ReturnType<typeof setup>) =>
    runAuthorizationCodeGrant({authorizationServer, client, callbackUri: "https://app.example/callback", codeProvider: s.codeProvider, scopes: ["openid"], options: s.options, signal: new AbortController().signal})

describe("runAuthorizationCodeGrant", () => {
    it("asks without interaction first, with PKCE and a nonce", async () => {
        const s = setup(success)

        await run(s)

        assert.equal(s.authorizationUrls.length, 1)
        const params = s.authorizationUrls[0]!.searchParams
        assert.equal(params.get("prompt"), "none")
        assert.equal(params.get("code_challenge_method"), "S256")
        assert.ok(params.get("code_challenge"))
        assert.ok(params.get("nonce"))
        assert.equal(params.get("scope"), "openid")
        assert.equal(params.get("client_id"), "client")
    })

    it("sends the code verifier to the token endpoint", async () => {
        const s = setup(success)

        await run(s)

        const verifier = s.tokenRequests[0]!.get("code_verifier")!
        assert.equal(s.tokenRequests[0]!.get("code"), "the-code")
        assert.equal(await oauth.calculatePKCECodeChallenge(verifier), s.authorizationUrls[0]!.searchParams.get("code_challenge"))
    })

    it("returns the ID token and its claims", async () => {
        const exp = Math.floor(Date.now() / 1000) + 1800
        const s = setup(success, exp)

        const response = await run(s)

        assert.equal(response.access_token, "access")
        assert.ok(response.id_token)
        assert.equal(oauth.getValidatedIdTokenClaims(response)!.exp, exp)
    })

    for (const error of ["login_required", "interaction_required", "consent_required"]) {
        it(`retries without prompt on ${error}`, async () => {
            const s = setup((url, attempt) => attempt === 1 ? failure(url, error) : success(url))

            await run(s)

            assert.equal(s.authorizationUrls.length, 2)
            assert.equal(s.authorizationUrls[0]!.searchParams.get("prompt"), "none")
            assert.equal(s.authorizationUrls[1]!.searchParams.has("prompt"), false)
            assert.equal(s.tokenRequests.length, 1)
        })
    }

    it("does not retry on other errors", async () => {
        const s = setup(url => failure(url, "access_denied"))

        await assert.rejects(run(s), oauth.AuthorizationResponseError)
        assert.equal(s.authorizationUrls.length, 1)
    })

    it("adds offline_access only when the server supports it", async () => {
        const s = setup(success)

        await runAuthorizationCodeGrant({authorizationServer: {...authorizationServer, scopes_supported: ["openid", "offline_access"]}, client, callbackUri: "https://app.example/callback", codeProvider: s.codeProvider, scopes: ["openid"], options: s.options, signal: new AbortController().signal})

        assert.equal(s.authorizationUrls[0]!.searchParams.get("scope"), "openid offline_access")
    })
})

describe("refreshGrant", () => {
    it("sends the refresh token", async () => {
        const requests: URLSearchParams[] = []
        const options = {
            [oauth.customFetch]: async (_: string, init: oauth.CustomFetchOptions<any, any>) => {
                requests.push(new URLSearchParams(init.body as string))

                return Response.json({access_token: "new", token_type: "Bearer"})
            },
        }

        const response = await refreshGrant({authorizationServer, client, refreshToken: "refresh", options})

        assert.equal(response.access_token, "new")
        assert.equal(requests[0]!.get("grant_type"), "refresh_token")
        assert.equal(requests[0]!.get("refresh_token"), "refresh")
    })
})
