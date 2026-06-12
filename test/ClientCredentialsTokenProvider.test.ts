import { inspect } from "node:util"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { ClientCredentialsTokenProvider } from "../src/ClientCredentialsTokenProvider.js"
import { createFakeAuthorizationServer, type FakeAuthorizationServer } from "./fakeAuthorizationServer.js"

const clientSecret = "very-secret-client-secret-0451"

const consoleMethods = ["log", "info", "warn", "error", "debug", "trace"] as const

let as: FakeAuthorizationServer

describe("ClientCredentialsTokenProvider", () => {
    beforeEach(async () => {
        // An issuer the provider's hard-coded issuer map recognizes.
        as = await createFakeAuthorizationServer({
            issuer: "https://solidcommunity.net",
            tokenEndpointAuthMethodsSupported: ["client_secret_basic"],
        })
        vi.stubGlobal("fetch", as.fetch)
    })

    afterEach(() => {
        vi.unstubAllGlobals()
        vi.restoreAllMocks()
    })

    // regression: PR #10 (fix/no-client-secret-logging) — f412896: upgrade() console.log'd
    // the client registration object, leaking client_secret into every consumer's console
    // on every token mint. No console call may carry the secret, however deeply nested.
    it("never writes the client secret to the console during upgrade", async () => {
        const spies = consoleMethods.map(method => vi.spyOn(console, method).mockImplementation(() => undefined))

        const provider = new ClientCredentialsTokenProvider("client-1", clientSecret)
        const upgraded = await provider.upgrade(new Request("https://pod.solidcommunity.net/private"))

        // The flow really ran with the secret in play: a minted token is attached.
        expect(upgraded.headers.get("Authorization")).toMatch(/^DPoP at-\d+$/)
        expect(as.tokenRequests.at(-1)?.get("grant_type")).toBe("client_credentials")

        for (const spy of spies) {
            for (const call of spy.mock.calls) {
                for (const argument of call) {
                    expect(inspect(argument, {depth: null})).not.toContain(clientSecret)
                }
            }
        }
    })
})
