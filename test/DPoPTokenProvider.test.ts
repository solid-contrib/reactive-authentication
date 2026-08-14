import assert from "node:assert/strict"
import { afterEach, beforeEach, describe, it, mock } from "node:test"
import { DPoPTokenProvider, type DPoPSession, type DPoPTokenProviderOptions } from "../dist/DPoPTokenProvider.js"
import { MemorySessionCache } from "../dist/MemorySessionCache.js"
import { createFakeAuthorizationServer, type FakeAuthorizationServer } from "./fakeAuthorizationServer.ts"

const callbackUri = "https://app.test/callback.html"

let as: FakeAuthorizationServer

function makeProvider(getCode = mock.fn((url: URL) => as.authorize(url)), options: DPoPTokenProviderOptions = {}) {
    const provider = new DPoPTokenProvider(callbackUri, getCode, async () => new URL(as.issuer), options)
    return {provider, getCode}
}

afterEach(async () => {
    mock.restoreAll()
    mock.timers.reset()
    await as.close()
})

describe("DPoPTokenProvider session cache", () => {
    beforeEach(async () => {
        as = await createFakeAuthorizationServer()
        mock.method(globalThis, "fetch", as.fetch)
    })

    it("attaches a DPoP-bound access token to the upgraded request", async () => {
        const {provider} = makeProvider()

        const upgraded = await provider.upgrade(new Request("https://pod.test/private"))

        assert.match(upgraded.headers.get("Authorization") ?? "", /^DPoP \S+$/)
        assert.ok(upgraded.headers.get("DPoP"))
    })

    it("runs the authorization flow once for concurrent upgrades (single-flight)", async () => {
        const {provider, getCode} = makeProvider()

        await Promise.all([
            provider.upgrade(new Request("https://pod.test/a")),
            provider.upgrade(new Request("https://pod.test/b")),
            provider.upgrade(new Request("https://pod.test/c")),
        ])

        assert.equal(getCode.mock.callCount(), 1)
        assert.equal(as.registrations.length, 1)
    })

    it("reuses the established session for later upgrades instead of re-prompting", async () => {
        const {provider, getCode} = makeProvider()

        const first = await provider.upgrade(new Request("https://pod.test/a"))
        const second = await provider.upgrade(new Request("https://pod.test/b"))

        assert.equal(getCode.mock.callCount(), 1)
        assert.equal(second.headers.get("Authorization"), first.headers.get("Authorization"))
    })

    it("signs a fresh DPoP proof per request while reusing the access token", async () => {
        const {provider} = makeProvider()

        const first = await provider.upgrade(new Request("https://pod.test/a"))
        const second = await provider.upgrade(new Request("https://pod.test/b"))

        assert.notEqual(second.headers.get("DPoP"), first.headers.get("DPoP"))
    })

    it("re-authenticates once the access token has expired", async () => {
        const {provider, getCode} = makeProvider()

        const first = await provider.upgrade(new Request("https://pod.test/a"))

        mock.timers.enable({apis: ["Date"], now: Date.now() + 3601 * 1000})
        const second = await provider.upgrade(new Request("https://pod.test/b"))

        assert.equal(getCode.mock.callCount(), 2)
        assert.notEqual(second.headers.get("Authorization"), first.headers.get("Authorization"))
    })

    it("does not cache a failed flow: the next upgrade retries", async () => {
        const getCode = mock.fn((url: URL) => as.authorize(url))
        getCode.mock.mockImplementationOnce(async () => {
            throw new Error("user closed the popup")
        })
        const {provider} = makeProvider(getCode)

        await assert.rejects(provider.upgrade(new Request("https://pod.test/a")), /user closed the popup/)

        const second = await provider.upgrade(new Request("https://pod.test/b"))

        assert.match(second.headers.get("Authorization") ?? "", /^DPoP \S+$/)
        assert.equal(getCode.mock.callCount(), 2)
    })
})

describe("DPoPTokenProvider session cache configuration", () => {
    beforeEach(async () => {
        as = await createFakeAuthorizationServer()
        mock.method(globalThis, "fetch", as.fetch)
    })

    it("defaults to one session per issuer", async () => {
        const {provider, getCode} = makeProvider()

        await provider.upgrade(new Request("https://pod.test/a"))
        await provider.upgrade(new Request("https://other.test/b"))

        assert.equal(getCode.mock.callCount(), 1)
    })

    it("honours a custom session key, so callers can scope sessions narrower than the issuer", async () => {
        const getCode = mock.fn((url: URL) => as.authorize(url))
        const {provider} = makeProvider(getCode, {getSessionKey: async request => new URL(request.url).origin})

        await provider.upgrade(new Request("https://pod.test/a"))
        await provider.upgrade(new Request("https://pod.test/b"))
        await provider.upgrade(new Request("https://other.test/c"))

        assert.equal(getCode.mock.callCount(), 2)
    })

    it("stores sessions in a caller supplied cache", async () => {
        const cache = new MemorySessionCache<DPoPSession>()
        const {provider} = makeProvider(undefined, {sessionCache: cache})

        await provider.upgrade(new Request("https://pod.test/a"))

        const session = await cache.get(new URL(as.issuer).href)
        assert.ok(session)
        assert.match(session.accessToken, /\S+/)
    })

    it("reuses a session already present in a shared cache, without prompting", async () => {
        const cache = new MemorySessionCache<DPoPSession>()
        const first = makeProvider(undefined, {sessionCache: cache})
        await first.provider.upgrade(new Request("https://pod.test/a"))

        const second = makeProvider(undefined, {sessionCache: cache})
        const upgraded = await second.provider.upgrade(new Request("https://pod.test/b"))

        assert.equal(second.getCode.mock.callCount(), 0)
        assert.equal(upgraded.headers.get("Authorization"), `DPoP ${(await cache.get(new URL(as.issuer).href))!.accessToken}`)
    })
})
