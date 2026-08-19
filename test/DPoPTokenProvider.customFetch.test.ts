import { test } from "node:test"
import assert from "node:assert/strict"
import { DPoPTokenProvider } from "../dist/DPoPTokenProvider.js"
import { ClientCredentialsTokenProvider } from "../dist/ClientCredentialsTokenProvider.js"
import type { GetCodeCallback } from "../dist/GetCodeCallback.js"

// Regression tests for the OIDC re-entrancy deadlock: token providers perform
// their own network requests (discovery, dynamic client registration, the token
// grant) through oauth4webapi, which defaults to `globalThis.fetch`. When an
// application patches the global fetch with an authenticating wrapper — e.g.
// `ReactiveFetchManager.registerGlobally()`, or a wrapper that single-flights
// concurrent requests onto one shared authentication attempt — those OIDC
// requests re-enter the wrapper mid-upgrade. A single-flighting wrapper then
// awaits the very authentication attempt its request is serving: a circular
// await that hangs login before the authorization popup/redirect ever opens.
//
// The fix: `TokenProviderOptions.fetch` pins the provider's own OIDC requests
// to a caller-supplied (pristine, pre-patch) fetch via oauth4webapi's
// `customFetch`, so they never ride the patched global.

const issuer = "https://op.example"
const callbackUri = "https://app.example/callback.html"
const clientId = "mock-client"

function jsonResponse(status: number, body: unknown): Response {
    return new Response(JSON.stringify(body), {status, headers: {"content-type": "application/json"}})
}

function base64url(value: string): string {
    return Buffer.from(value).toString("base64url")
}

/** An ID Token with valid claims and a placeholder signature (oauth4webapi does not validate the signature of tokens received directly from the token endpoint). */
function idToken(nonce: string | undefined): string {
    const now = Math.floor(Date.now() / 1000)
    const header = {alg: "RS256", typ: "JWT"}
    const payload = {
        iss: issuer,
        sub: "https://alice.example/profile/card#me",
        aud: clientId,
        exp: now + 600,
        iat: now,
        webid: "https://alice.example/profile/card#me",
        ...(nonce === undefined ? {} : {nonce}),
    }
    return `${base64url(JSON.stringify(header))}.${base64url(JSON.stringify(payload))}.${base64url("mock-signature")}`
}

/** An in-process mock OpenID Provider, exposed as a fetch implementation. */
function mockOpFetch(state: {nonce?: string, requests: string[]}): typeof globalThis.fetch {
    return async (input, init) => {
        const url = new URL(input instanceof Request ? input.url : String(input))
        state.requests.push(url.pathname)

        switch (url.pathname) {
            case "/.well-known/openid-configuration":
                return jsonResponse(200, {
                    issuer,
                    authorization_endpoint: `${issuer}/authorize`,
                    token_endpoint: `${issuer}/token`,
                    registration_endpoint: `${issuer}/register`,
                    code_challenge_methods_supported: ["S256"],
                    token_endpoint_auth_methods_supported: ["client_secret_basic"],
                })
            case "/register":
                return jsonResponse(201, {
                    client_id: clientId,
                    redirect_uris: [callbackUri],
                    response_types: ["code"],
                    token_endpoint_auth_method: "none",
                })
            case "/token":
                return jsonResponse(200, {
                    access_token: "mock-access-token",
                    token_type: "DPoP",
                    expires_in: 3600,
                    scope: "openid webid",
                    id_token: idToken(state.nonce),
                })
            default:
                throw new Error(`Unexpected request to mock OP: ${url}`)
        }
    }
}

/** Echoes the authorization code straight back, capturing the nonce so the mock OP can bind it into the ID Token. */
function getCodeCallback(state: {nonce?: string}): GetCodeCallback {
    return async authorizationUri => {
        state.nonce = authorizationUri.searchParams.get("nonce") ?? undefined
        return `${callbackUri}?code=mock-code&state=${authorizationUri.searchParams.get("state")}`
    }
}

test("DPoP auth-code login resolves even when globalThis.fetch is patched with a deadlocking wrapper, when a pristine fetch is pinned", {timeout: 15_000}, async t => {
    const state: {nonce?: string, requests: string[]} = {requests: []}

    // Simulate an app-installed single-flighting authenticated-fetch wrapper:
    // mid-login, any request through it awaits the in-flight authentication
    // attempt — i.e. from the provider's perspective, it never resolves.
    const realFetch = globalThis.fetch
    let patchedCalls = 0
    globalThis.fetch = (() => {
        patchedCalls++
        return new Promise<Response>(() => {})
    }) as typeof globalThis.fetch
    t.after(() => {
        globalThis.fetch = realFetch
    })

    const provider = new DPoPTokenProvider(
        callbackUri,
        getCodeCallback(state),
        async () => new URL(issuer),
        {fetch: mockOpFetch(state)},
    )

    const upgraded = await provider.upgrade(new Request("https://pod.example/private/resource"))

    assert.match(upgraded.headers.get("Authorization") ?? "", /^DPoP mock-access-token$/)
    assert.ok(upgraded.headers.get("DPoP"))
    assert.deepEqual(state.requests, ["/.well-known/openid-configuration", "/register", "/token"])
    assert.equal(patchedCalls, 0, "the provider's OIDC requests must not ride the patched global fetch")
})

test("client-credentials login resolves under a patched globalThis.fetch when a pristine fetch is pinned", {timeout: 15_000}, async t => {
    const state: {nonce?: string, requests: string[]} = {requests: []}

    const realFetch = globalThis.fetch
    let patchedCalls = 0
    globalThis.fetch = (() => {
        patchedCalls++
        return new Promise<Response>(() => {})
    }) as typeof globalThis.fetch
    t.after(() => {
        globalThis.fetch = realFetch
    })

    // The client-credentials provider derives the issuer from the request URL.
    const provider = new ClientCredentialsTokenProvider(clientId, "mock-secret", {fetch: mockOpFetchAt("https://solidcommunity.net", state)})

    const upgraded = await provider.upgrade(new Request("https://alice.solidcommunity.net/private/resource"))

    assert.match(upgraded.headers.get("Authorization") ?? "", /^DPoP mock-access-token$/)
    assert.equal(patchedCalls, 0, "the provider's OIDC requests must not ride the patched global fetch")
})

test("without options the provider still defaults to globalThis.fetch (backwards compatible)", {timeout: 15_000}, async t => {
    const state: {nonce?: string, requests: string[]} = {requests: []}

    const realFetch = globalThis.fetch
    globalThis.fetch = mockOpFetch(state)
    t.after(() => {
        globalThis.fetch = realFetch
    })

    const provider = new DPoPTokenProvider(callbackUri, getCodeCallback(state), async () => new URL(issuer))

    const upgraded = await provider.upgrade(new Request("https://pod.example/private/resource"))

    assert.match(upgraded.headers.get("Authorization") ?? "", /^DPoP mock-access-token$/)
    assert.deepEqual(state.requests, ["/.well-known/openid-configuration", "/register", "/token"])
})

/** A mock OP for a different issuer (client-credentials flow: no registration, no ID Token nonce). */
function mockOpFetchAt(opIssuer: string, state: {requests: string[]}): typeof globalThis.fetch {
    return async (input, init) => {
        const url = new URL(input instanceof Request ? input.url : String(input))
        state.requests.push(url.pathname)

        switch (url.pathname) {
            case "/.well-known/openid-configuration":
                return jsonResponse(200, {
                    issuer: opIssuer,
                    authorization_endpoint: `${opIssuer}/authorize`,
                    token_endpoint: `${opIssuer}/token`,
                    token_endpoint_auth_methods_supported: ["client_secret_basic"],
                })
            case "/token":
                return jsonResponse(200, {
                    access_token: "mock-access-token",
                    token_type: "DPoP",
                    expires_in: 3600,
                    scope: "webid",
                })
            default:
                throw new Error(`Unexpected request to mock OP: ${url}`)
        }
    }
}
