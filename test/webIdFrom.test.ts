import { afterEach, describe, expect, it, vi } from "vitest"
import type { TokenEndpointResponse } from "oauth4webapi"
import { DPoPTokenProvider } from "../src/DPoPTokenProvider.js"
import { webIdFrom } from "../src/webIdFrom.js"
import { createFakeAuthorizationServer, type FakeAuthorizationServerOptions } from "./fakeAuthorizationServer.js"

const callbackUri = "https://app.test/callback.html"

/**
 * oauth4webapi only hands out the claims of id_tokens it validated itself, so
 * the response under test comes from a real flow rather than a literal.
 */
async function signIn(options: FakeAuthorizationServerOptions = {}): Promise<TokenEndpointResponse> {
    const as = await createFakeAuthorizationServer(options)
    vi.stubGlobal("fetch", as.fetch)

    const provider = new DPoPTokenProvider(callbackUri, url => as.authorize(url), async () => new URL(as.issuer))
    await provider.upgrade(new Request("https://pod.test/private"))

    const response = await provider.tokenEndpointResponse(new URL(as.issuer))
    if (response === undefined) {
        throw new Error("the flow established no session")
    }

    return response
}

afterEach(() => {
    vi.unstubAllGlobals()
})

describe("webIdFrom", () => {
    it("returns the WebID the id_token asserted", async () => {
        expect(webIdFrom(await signIn())).toBe("https://pod.test/profile/card#me")
    })

    it("returns nothing when the id_token carries no webid claim", async () => {
        expect(webIdFrom(await signIn({webId: null}))).toBeUndefined()
    })

    it("returns nothing when the response carries no id_token", () => {
        const response: TokenEndpointResponse = {access_token: "at-1", token_type: "dpop"}

        expect(webIdFrom(response)).toBeUndefined()
    })
})
