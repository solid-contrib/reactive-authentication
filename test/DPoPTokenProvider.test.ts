import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { DPoPTokenProvider } from "../src/DPoPTokenProvider.js"
import { createFakeAuthorizationServer, type FakeAuthorizationServer } from "./fakeAuthorizationServer.js"

const callbackUri = "https://app.test/callback.html"

let as: FakeAuthorizationServer

function makeProvider(getCode = vi.fn((url: URL) => as.authorize(url))) {
    const provider = new DPoPTokenProvider(callbackUri, getCode, async () => new URL(as.issuer))
    return {provider, getCode}
}

afterEach(() => {
    vi.unstubAllGlobals()
    vi.useRealTimers()
})

describe("DPoPTokenProvider session cache", () => {
    beforeEach(async () => {
        as = await createFakeAuthorizationServer()
        vi.stubGlobal("fetch", as.fetch)
    })

    it("attaches a DPoP-bound access token to the upgraded request", async () => {
        const {provider} = makeProvider()

        const upgraded = await provider.upgrade(new Request("https://pod.test/private"))

        expect(upgraded.headers.get("Authorization")).toMatch(/^DPoP at-\d+$/)
        expect(upgraded.headers.get("DPoP")).toBeTruthy()
    })

    it("runs the authorization flow once for concurrent upgrades (single-flight)", async () => {
        const {provider, getCode} = makeProvider()

        await Promise.all([
            provider.upgrade(new Request("https://pod.test/a")),
            provider.upgrade(new Request("https://pod.test/b")),
            provider.upgrade(new Request("https://pod.test/c")),
        ])

        expect(getCode).toHaveBeenCalledTimes(1)
        expect(as.registrations).toHaveLength(1)
    })

    it("reuses the established session for later upgrades instead of re-prompting", async () => {
        const {provider, getCode} = makeProvider()

        const first = await provider.upgrade(new Request("https://pod.test/a"))
        const second = await provider.upgrade(new Request("https://pod.test/b"))

        expect(getCode).toHaveBeenCalledTimes(1)
        expect(second.headers.get("Authorization")).toBe(first.headers.get("Authorization"))
    })

    it("signs a fresh DPoP proof per request while reusing the access token", async () => {
        const {provider} = makeProvider()

        const first = await provider.upgrade(new Request("https://pod.test/a"))
        const second = await provider.upgrade(new Request("https://pod.test/b"))

        expect(second.headers.get("DPoP")).not.toBe(first.headers.get("DPoP"))
    })

    it("re-authenticates once the access token has expired", async () => {
        const {provider, getCode} = makeProvider()

        const first = await provider.upgrade(new Request("https://pod.test/a"))

        // Step past the reported expiry (minus the skew allowance).
        vi.useFakeTimers()
        vi.setSystemTime(Date.now() + 3601 * 1000)

        const second = await provider.upgrade(new Request("https://pod.test/b"))

        expect(getCode).toHaveBeenCalledTimes(2)
        expect(second.headers.get("Authorization")).not.toBe(first.headers.get("Authorization"))
    })

    it("does not cache a failed flow: the next upgrade retries", async () => {
        const getCode = vi.fn((url: URL) => as.authorize(url))
        getCode.mockRejectedValueOnce(new Error("user closed the popup"))
        const {provider} = makeProvider(getCode)

        await expect(provider.upgrade(new Request("https://pod.test/a"))).rejects.toThrow("user closed the popup")

        const second = await provider.upgrade(new Request("https://pod.test/b"))

        expect(second.headers.get("Authorization")).toMatch(/^DPoP at-\d+$/)
        expect(getCode).toHaveBeenCalledTimes(2)
    })
})

describe("DPoPTokenProvider token endpoint response", () => {
    beforeEach(async () => {
        as = await createFakeAuthorizationServer()
        vi.stubGlobal("fetch", as.fetch)
    })

    it("reports the response the session rests on once a flow has completed", async () => {
        const {provider} = makeProvider()

        const upgraded = await provider.upgrade(new Request("https://pod.test/private"))
        const reported = await provider.tokenEndpointResponse(new URL(as.issuer))

        expect(upgraded.headers.get("Authorization")).toBe(`DPoP ${reported?.access_token}`)
    })

    it("reports nothing before a flow has run, without starting one", async () => {
        const {provider, getCode} = makeProvider()

        await expect(provider.tokenEndpointResponse(new URL(as.issuer))).resolves.toBeUndefined()
        expect(getCode).not.toHaveBeenCalled()
    })

    it("reports the renewed response once the session has been re-established", async () => {
        const {provider} = makeProvider()

        await provider.upgrade(new Request("https://pod.test/a"))
        const first = await provider.tokenEndpointResponse(new URL(as.issuer))

        // Step past the reported expiry (minus the skew allowance).
        vi.useFakeTimers()
        vi.setSystemTime(Date.now() + 3601 * 1000)

        await provider.upgrade(new Request("https://pod.test/b"))
        const second = await provider.tokenEndpointResponse(new URL(as.issuer))

        expect(second?.access_token).not.toBe(first?.access_token)
    })

    it("reports nothing for a flow that fails, rather than the failure", async () => {
        let failCode!: (reason: Error) => void
        const getCode = vi.fn(() => new Promise<string>((_, reject) => {failCode = reject}))
        const {provider} = makeProvider(getCode)

        const upgrade = provider.upgrade(new Request("https://pod.test/a"))
        await vi.waitUntil(() => getCode.mock.calls.length === 1)
        const reported = provider.tokenEndpointResponse(new URL(as.issuer))
        failCode(new Error("user closed the popup"))

        await expect(upgrade).rejects.toThrow("user closed the popup")
        await expect(reported).resolves.toBeUndefined()
    })
})
