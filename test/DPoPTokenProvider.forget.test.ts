import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { DPoPTokenProvider } from "../src/DPoPTokenProvider.js"
import { SessionForgottenError } from "../src/SessionForgottenError.js"
import { createFakeAuthorizationServer, type FakeAuthorizationServer } from "./fakeAuthorizationServer.js"

const callbackUri = "https://app.test/callback.html"

let as: FakeAuthorizationServer

function makeProvider(getCode = vi.fn((url: URL) => as.authorize(url)), getIssuer = async () => new URL(as.issuer)) {
    const provider = new DPoPTokenProvider(callbackUri, getCode, getIssuer)
    return {provider, getCode}
}

afterEach(() => {
    vi.unstubAllGlobals()
    vi.useRealTimers()
})

describe("DPoPTokenProvider.forget (definitive session teardown)", () => {
    beforeEach(async () => {
        as = await createFakeAuthorizationServer({
            issueRefreshTokens: true,
            scopesSupported: ["openid", "webid", "offline_access"],
            grantTypesSupported: ["authorization_code", "refresh_token"],
        })
        vi.stubGlobal("fetch", as.fetch)
    })

    it("drops the session so the next upgrade runs a fresh authorization flow", async () => {
        const {provider, getCode} = makeProvider()

        await provider.upgrade(new Request("https://pod.test/a"))
        expect(getCode).toHaveBeenCalledTimes(1)
        expect(as.registrations).toHaveLength(1)

        await provider.forget(new Request("https://pod.test/a"))

        await provider.upgrade(new Request("https://pod.test/b"))
        expect(getCode).toHaveBeenCalledTimes(2) // a brand-new interactive flow, not a silent reuse
        expect(as.registrations).toHaveLength(2)
    })

    it("is definitive where invalidate is transient (drops the refresh token vs keeps it)", async () => {
        const {provider, getCode} = makeProvider()

        // Transient: invalidate marks the access token stale but KEEPS the refresh
        // token, so the next upgrade renews silently via the refresh grant.
        const first = await provider.upgrade(new Request("https://pod.test/a"))
        await provider.invalidate(first)
        await provider.upgrade(new Request("https://pod.test/b"))
        expect(getCode).toHaveBeenCalledTimes(1) // no new popup
        expect(as.tokenRequests.at(-1)?.get("grant_type")).toBe("refresh_token")

        // Definitive: forget discards the whole session (refresh token included),
        // so the next upgrade must re-authorize interactively.
        await provider.forget(new Request("https://pod.test/c"))
        await provider.upgrade(new Request("https://pod.test/d"))
        expect(getCode).toHaveBeenCalledTimes(2) // a fresh interactive flow
        expect(as.tokenRequests.at(-1)?.get("grant_type")).toBe("authorization_code")
    })

    it("fails closed when a session is forgotten mid-upgrade, and does not resurrect it", async () => {
        // A getCode we can hold open, to keep the first upgrade in flight past the
        // point where it captured the session's generation.
        const entered = Promise.withResolvers<void>()
        const proceed = Promise.withResolvers<void>()
        const getCode = vi.fn(async (url: URL) => {
            entered.resolve()
            await proceed.promise
            return as.authorize(url)
        })
        const {provider} = makeProvider(getCode)

        const upgrading = provider.upgrade(new Request("https://pod.test/private"))
        await entered.promise // the upgrade is now parked inside the authorization flow

        // The user logs out while the request is still in flight.
        await provider.forget(new Request("https://pod.test/private"))

        proceed.resolve() // let the (now superseded) authorization flow complete

        // The in-flight request must NOT complete carrying the forgotten session's
        // credentials — it fails closed instead.
        await expect(upgrading).rejects.toBeInstanceOf(SessionForgottenError)

        // …and the mid-flight session was not left cached (no resurrection): the
        // next upgrade needs a fresh authorization.
        const next = await provider.upgrade(new Request("https://pod.test/again"))
        expect(next.headers.get("Authorization")).toMatch(/^DPoP /)
        expect(getCode).toHaveBeenCalledTimes(2)
    })

    it("is per-issuer: forgetting one issuer does not fail-close an in-flight upgrade for another", async () => {
        const entered = Promise.withResolvers<void>()
        const proceed = Promise.withResolvers<void>()
        const getCode = vi.fn(async (url: URL) => {
            entered.resolve()
            await proceed.promise
            return as.authorize(url)
        })
        // /drop resolves to a different issuer than the pod being authenticated.
        const getIssuer = async (request: Request) =>
            new URL(request.url.includes("/drop") ? "https://other.test" : as.issuer)
        const {provider} = makeProvider(getCode, getIssuer)

        const upgrading = provider.upgrade(new Request("https://pod.test/keep"))
        await entered.promise

        // Forget a DIFFERENT issuer while the pod.test upgrade is in flight.
        await provider.forget(new Request("https://pod.test/drop"))

        proceed.resolve()

        // The pod.test upgrade is unaffected and completes normally.
        const upgraded = await upgrading
        expect(upgraded.headers.get("Authorization")).toMatch(/^DPoP /)
    })

    it("forget with no established session is a safe no-op", async () => {
        const {provider, getCode} = makeProvider()

        await expect(provider.forget(new Request("https://pod.test/x"))).resolves.toBeUndefined()

        // A later upgrade still works (and is not spuriously fenced by the bump).
        const upgraded = await provider.upgrade(new Request("https://pod.test/x"))
        expect(upgraded.headers.get("Authorization")).toMatch(/^DPoP /)
        expect(getCode).toHaveBeenCalledTimes(1)
    })
})
