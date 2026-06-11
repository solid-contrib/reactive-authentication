import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { DPoPTokenProvider } from "../src/DPoPTokenProvider.js"
import { ReactiveFetchManager } from "../src/ReactiveFetchManager.js"
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

    it("sends prompt=consent on the interactive attempt so strict servers honour offline_access (OIDC Core §11)", async () => {
        as = await createFakeAuthorizationServer({
            issueRefreshTokens: true,
            scopesSupported: ["openid", "webid", "offline_access"],
            enforceOfflineAccessConsent: true,
        })
        vi.stubGlobal("fetch", as.fetch)
        const {provider, getCode} = makeProvider()

        const first = await provider.upgrade(new Request("https://pod.test/a"))

        expect(first.headers.get("Authorization")).toMatch(/^DPoP at-\d+$/)
        expect(getCode).toHaveBeenCalledTimes(2) // silent attempt → login_required → interactive retry
        expect(as.authorizationRequests.at(-1)?.prompt).toBe("consent")

        // The strict server issued a refresh token, so expiry renews silently.
        vi.useFakeTimers()
        vi.setSystemTime(Date.now() + 3601 * 1000)
        await provider.upgrade(new Request("https://pod.test/b"))

        expect(getCode).toHaveBeenCalledTimes(2) // no further interaction
        expect(as.tokenRequests.at(-1)?.get("grant_type")).toBe("refresh_token")
    })

    it("retries the refresh grant once when the server demands a DPoP nonce", async () => {
        as = await createFakeAuthorizationServer({
            issueRefreshTokens: true,
            scopesSupported: ["openid", "webid", "offline_access"],
            refreshRequiresDPoPNonce: true,
        })
        vi.stubGlobal("fetch", as.fetch)
        const {provider, getCode} = makeProvider()

        await provider.upgrade(new Request("https://pod.test/a"))

        vi.useFakeTimers()
        vi.setSystemTime(Date.now() + 3601 * 1000)

        const second = await provider.upgrade(new Request("https://pod.test/b"))

        expect(getCode).toHaveBeenCalledTimes(1) // refreshed silently despite the nonce challenge
        expect(second.headers.get("Authorization")).toMatch(/^DPoP at-\d+$/)

        const refreshRequests = as.tokenRequests.filter(r => r.get("grant_type") === "refresh_token")
        expect(refreshRequests).toHaveLength(2) // challenged once, then accepted with the nonce
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

describe("renewal after a rejected upgrade (401-once retry)", () => {
    /** Tokens the fake resource server no longer accepts. */
    let revokedTokens: Set<string>
    /** Bearer parts of the Authorization headers the resource server saw, oldest first. */
    let presentedTokens: string[]

    /** Routes pod.test to a fake resource server (401 unless a non-revoked token is presented), everything else to the fake AS. */
    function combinedFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
        const request = new Request(input, init)
        if (new URL(request.url).origin !== "https://pod.test") {
            return as.fetch(input, init)
        }

        const authorization = request.headers.get("Authorization")
        if (authorization === null || !authorization.startsWith("DPoP ")) {
            return Promise.resolve(new Response(null, {status: 401}))
        }
        const token = authorization.slice("DPoP ".length)

        presentedTokens.push(token)
        return Promise.resolve(revokedTokens.has(token) ? new Response(null, {status: 401}) : new Response("ok"))
    }

    beforeEach(async () => {
        as = await createFakeAuthorizationServer({
            issueRefreshTokens: true,
            scopesSupported: ["openid", "webid", "offline_access"],
        })
        revokedTokens = new Set()
        presentedTokens = []
        vi.stubGlobal("fetch", combinedFetch)
    })

    it("renews the session and retries once when the upgraded request is still rejected", async () => {
        const {provider, getCode} = makeProvider()
        const manager = new ReactiveFetchManager([provider])

        const first = await manager.fetch("https://pod.test/private")
        expect(first.status).toBe(200)

        // Revoke the established token server-side (no expiry has passed).
        revokedTokens.add(presentedTokens.at(-1)!)

        const second = await manager.fetch("https://pod.test/private")

        expect(second.status).toBe(200)
        expect(getCode).toHaveBeenCalledTimes(1) // renewed via the refresh grant, no new popup
        expect(as.tokenRequests.at(-1)?.get("grant_type")).toBe("refresh_token")
    })

    it("gives up after one renewal: a still-rejected retry surfaces the 401 unchanged", async () => {
        const {provider} = makeProvider()
        const manager = new ReactiveFetchManager([provider])

        await manager.fetch("https://pod.test/private")

        // Reject everything from now on, whatever token is presented.
        const reject = {has: () => true} as unknown as Set<string>
        revokedTokens = reject

        const tokenPresentationsBefore = presentedTokens.length
        const response = await manager.fetch("https://pod.test/private")

        expect(response.status).toBe(401)
        // Bounded: the cached token once, the renewed token once — then give up.
        expect(presentedTokens.length - tokenPresentationsBefore).toBe(2)
    })

    it("ignores invalidation for a token that is no longer the cached one", async () => {
        const {provider} = makeProvider()

        const first = await provider.upgrade(new Request("https://pod.test/a"))
        await provider.invalidate(first)
        const second = await provider.upgrade(new Request("https://pod.test/b"))
        expect(second.headers.get("Authorization")).not.toBe(first.headers.get("Authorization"))

        // Replaying the stale rejection must not invalidate the renewed session.
        const tokenRequestsBefore = as.tokenRequests.length
        await provider.invalidate(first)
        const third = await provider.upgrade(new Request("https://pod.test/c"))

        expect(third.headers.get("Authorization")).toBe(second.headers.get("Authorization"))
        expect(as.tokenRequests.length).toBe(tokenRequestsBefore)
    })
})
