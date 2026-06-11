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
