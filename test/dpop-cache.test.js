import assert from "node:assert/strict"
import { test } from "node:test"
import { IDBFactory } from "fake-indexeddb"
import { MemoryCache } from "../dist/MemoryCache.js"
import { IndexedDbCache } from "../dist/IndexedDbCache.js"
import { DPoPTokenProvider } from "../dist/DPoPTokenProvider.js"

const url = "https://pod.example/resource"
const callback = "https://app.example/callback"
const authorizationServer = {
    issuer: "https://idp.example",
    authorization_endpoint: "https://idp.example/authorize",
    token_endpoint: "https://idp.example/token",
    code_challenge_methods_supported: ["S256"],
}
const client = { client_id: "app", redirect_uris: [callback], response_types: ["code"] }
const unreachable = {
    async getCode() { throw new Error("unexpected authorization") },
    async getAuthorizationServer() { throw new Error("unexpected discovery") },
    async getClient() { throw new Error("unexpected registration") },
}
const providerFor = cache => new DPoPTokenProvider(callback, unreachable, unreachable, unreachable, cache)
const claims = jwt => JSON.parse(Buffer.from(jwt.split(".")[1], "base64url"))

async function entry(expired = false) {
    return {
        created: expired ? 0 : Date.now(),
        tokenResult: { access_token: "access", token_type: "dpop", refresh_token: "refresh-1", expires_in: 3600 },
        dpopKey: await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]),
        client, authorizationServer,
    }
}

test("restored IndexedDB credentials produce a fresh request-bound proof each time", async () => {
    const factory = new IDBFactory()
    await new IndexedDbCache("tokens", factory).set(url, await entry())
    const provider = providerFor(new IndexedDbCache("tokens", factory))
    const first = await provider.upgrade(new Request(url))
    const second = await provider.upgrade(new Request(url, { method: "POST" }))
    assert.equal(first.headers.get("Authorization"), "DPoP access")
    const firstProof = claims(first.headers.get("DPoP"))
    const secondProof = claims(second.headers.get("DPoP"))
    assert.equal(firstProof.htm, "GET")
    assert.equal(secondProof.htm, "POST")
    assert.equal(firstProof.htu, url)
    assert.notEqual(firstProof.jti, secondProof.jti)
    await assert.rejects(provider.upgrade(new Request("https://pod.example/other")), /unexpected discovery/)
})

test("two providers sharing persistent credentials rotate once and await durable writes", async t => {
    const factory = new IDBFactory()
    const cache = new IndexedDbCache("rotation", factory)
    const original = await entry(true)
    await cache.set(url, original)
    let grants = 0
    t.mock.method(globalThis, "fetch", async (input, options) => {
        assert.equal(String(input), authorizationServer.token_endpoint)
        assert.equal(new URLSearchParams(options.body).get("refresh_token"), "refresh-1")
        assert.equal(await cache.get(url), undefined, "consumed token must not remain durable")
        grants++
        return Response.json({ access_token: "renewed", token_type: "DPoP", refresh_token: "refresh-2", expires_in: 3600 })
    })
    const results = await Promise.all([
        providerFor(cache).upgrade(new Request(url)),
        providerFor(new IndexedDbCache("rotation", factory)).upgrade(new Request(url)),
    ])
    assert.equal(grants, 1)
    assert.ok(results.every(result => result.headers.get("Authorization") === "DPoP renewed"))
    const restored = await new IndexedDbCache("rotation", factory).get(url)
    assert.equal(restored.tokenResult.refresh_token, "refresh-2")
    assert.deepEqual(await crypto.subtle.exportKey("jwk", restored.dpopKey.publicKey), await crypto.subtle.exportKey("jwk", original.dpopKey.publicKey))
})

test("refresh without rotation retains the previous refresh token", async t => {
    const cache = new MemoryCache()
    await cache.set(url, await entry(true))
    t.mock.method(globalThis, "fetch", async () => Response.json({ access_token: "renewed", token_type: "DPoP", expires_in: 3600 }))
    await providerFor(cache).upgrade(new Request(url))
    assert.equal((await cache.get(url)).tokenResult.refresh_token, "refresh-1")
})

test("failed durable rotation does not expose credentials or leave the consumed refresh token", async t => {
    const cache = new MemoryCache()
    await cache.set(url, await entry(true))
    t.mock.method(globalThis, "fetch", async () => Response.json({ access_token: "renewed", token_type: "DPoP", refresh_token: "refresh-2", expires_in: 3600 }))
    t.mock.method(cache, "set", async () => { throw new Error("quota") })
    await assert.rejects(providerFor(cache).upgrade(new Request(url)), /quota/)
    assert.equal(await cache.get(url), undefined)
})

test("failed invalidation prevents consumption of the refresh token", async t => {
    const cache = new MemoryCache()
    await cache.set(url, await entry(true))
    t.mock.method(cache, "delete", async () => { throw new Error("denied") })
    const fetch = t.mock.method(globalThis, "fetch", async () => { throw new Error("must not fetch") })
    await assert.rejects(providerFor(cache).upgrade(new Request(url)), /denied/)
    assert.equal(fetch.mock.callCount(), 0)
})

test("invalid_grant evicts before reauthorization; other refresh errors propagate", async t => {
    const cache = new MemoryCache()
    let invalid = true
    t.mock.method(globalThis, "fetch", async () => Response.json({ error: invalid ? "invalid_grant" : "temporarily_unavailable" }, { status: 400 }))
    await cache.set(url, await entry(true))
    await assert.rejects(providerFor(cache).upgrade(new Request(url)), /unexpected discovery/)
    assert.equal(await cache.get(url), undefined)
    invalid = false
    await cache.set(url, await entry(true))
    await assert.rejects(providerFor(cache).upgrade(new Request(url)), error => error.error === "temporarily_unavailable")
    assert.equal(await cache.get(url), undefined)
})

test("fresh authorization caches only successful results and preserves constructor defaults", async t => {
    const cache = new MemoryCache()
    let cancel = true
    let nonce
    let codeCalls = 0
    const codeProvider = { async getCode(authorizationUrl) {
        codeCalls++
        if (cancel) throw new Error("cancelled")
        nonce = authorizationUrl.searchParams.get("nonce")
        const response = new URL(callback)
        response.searchParams.set("code", "code")
        response.searchParams.set("state", authorizationUrl.searchParams.get("state"))
        return { value: response.href, [Symbol.dispose]() {} }
    } }
    const signingKeys = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"])
    t.mock.method(globalThis, "fetch", async () => {
        const now = Math.floor(Date.now() / 1000)
        const jwt = [ { alg: "ES256" }, { iss: authorizationServer.issuer, aud: client.client_id, sub: "user", nonce, iat: now, exp: now + 3600 } ].map(value => Buffer.from(JSON.stringify(value)).toString("base64url")).join(".")
        const signature = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, signingKeys.privateKey, new TextEncoder().encode(jwt))
        return Response.json({ access_token: "fresh", token_type: "DPoP", expires_in: 3600, id_token: `${jwt}.${Buffer.from(signature).toString("base64url")}` })
    })
    const asProvider = { async getAuthorizationServer() { return authorizationServer } }
    const clientProvider = { async getClient() { return { ...client, id_token_signed_response_alg: "ES256" } } }
    const provider = new DPoPTokenProvider(callback, codeProvider, asProvider, clientProvider, cache)
    await assert.rejects(provider.upgrade(new Request(url)), /cancelled/)
    assert.equal(await cache.get(url), undefined)
    cancel = false
    const results = await Promise.all([provider.upgrade(new Request(url)), provider.upgrade(new Request(url))])
    assert.ok(results.every(result => result.headers.get("Authorization") === "DPoP fresh"))
    assert.equal(codeCalls, 2)
    assert.equal((await cache.get(url)).tokenResult.access_token, "fresh")
    const defaults = new DPoPTokenProvider(callback, codeProvider, asProvider, clientProvider)
    await defaults.upgrade(new Request(url))
    await defaults.upgrade(new Request(url))
    assert.equal(codeCalls, 3)
})
