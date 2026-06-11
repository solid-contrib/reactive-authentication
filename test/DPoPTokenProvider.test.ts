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

describe("DPoPTokenProvider refresh tokens", () => {
    beforeEach(async () => {
        as = await createFakeAuthorizationServer({
            issueRefreshTokens: true,
            scopesSupported: ["openid", "webid", "offline_access"],
            grantTypesSupported: ["authorization_code", "refresh_token"],
        })
        vi.stubGlobal("fetch", as.fetch)
    })

    it("opts in where supported: registers the refresh_token grant and requests offline_access", async () => {
        const {provider} = makeProvider()

        await provider.upgrade(new Request("https://pod.test/a"))

        expect(as.registrations[0]?.grant_types).toEqual(["authorization_code", "refresh_token"])
        expect(as.authorizationRequests[0]?.scope).toBe("openid webid offline_access")
    })

    it("does not change the requests for servers without refresh support", async () => {
        as = await createFakeAuthorizationServer()
        vi.stubGlobal("fetch", as.fetch)
        const {provider} = makeProvider()

        await provider.upgrade(new Request("https://pod.test/a"))

        expect(as.registrations[0]?.grant_types).toBeUndefined()
        expect(as.authorizationRequests[0]?.scope).toBe("openid webid")
    })

    it("refreshes an expired access token without user interaction", async () => {
        const {provider, getCode} = makeProvider()

        const first = await provider.upgrade(new Request("https://pod.test/a"))

        vi.useFakeTimers()
        vi.setSystemTime(Date.now() + 3601 * 1000)

        const second = await provider.upgrade(new Request("https://pod.test/b"))

        expect(getCode).toHaveBeenCalledTimes(1) // no new popup
        expect(second.headers.get("Authorization")).not.toBe(first.headers.get("Authorization"))
        expect(as.tokenRequests.at(-1)?.get("grant_type")).toBe("refresh_token")
    })

    it("adopts the rotated refresh token (a second expiry refreshes with the new one)", async () => {
        const {provider, getCode} = makeProvider()

        await provider.upgrade(new Request("https://pod.test/a"))

        vi.useFakeTimers()
        vi.setSystemTime(Date.now() + 3601 * 1000)
        await provider.upgrade(new Request("https://pod.test/b"))

        vi.setSystemTime(Date.now() + 3601 * 1000)
        const third = await provider.upgrade(new Request("https://pod.test/c"))

        expect(getCode).toHaveBeenCalledTimes(1)
        expect(third.headers.get("Authorization")).toMatch(/^DPoP at-\d+$/)

        const refreshRequests = as.tokenRequests.filter(r => r.get("grant_type") === "refresh_token")
        expect(refreshRequests).toHaveLength(2)
        // The second refresh presented a different (rotated) token than the first.
        expect(refreshRequests[1]?.get("refresh_token")).not.toBe(refreshRequests[0]?.get("refresh_token"))
    })

    it("falls back to a new authorization-code flow when the refresh grant fails", async () => {
        const {provider, getCode} = makeProvider()

        await provider.upgrade(new Request("https://pod.test/a"))

        // Revoke server-side: the next refresh attempt gets invalid_grant.
        as.activeRefreshTokens.clear()

        vi.useFakeTimers()
        vi.setSystemTime(Date.now() + 3601 * 1000)

        const second = await provider.upgrade(new Request("https://pod.test/b"))

        expect(getCode).toHaveBeenCalledTimes(2) // re-authorized
        expect(second.headers.get("Authorization")).toMatch(/^DPoP at-\d+$/)
    })
})
