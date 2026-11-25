import assert from "node:assert/strict"
import {describe, it} from "node:test"
import * as oauth from "oauth4webapi"
import type {AuthorizationServerProvider} from "../src/AuthorizationServerProvider.js"
import {FallbackAuthorizationServerProvider} from "../src/FallbackAuthorizationServerProvider.js"

const issuer = new URL("https://as.example")
const primaryServer: oauth.AuthorizationServer = {issuer: "https://as.example"}
const fallbackServer: oauth.AuthorizationServer = {issuer: "https://as.example", token_endpoint: "https://as.example/fallback"}

function createProvider(result: () => Promise<oauth.AuthorizationServer>, calls: URL[] = []): AuthorizationServerProvider {
    return {
        getAuthorizationServer: async (requested) => {
            calls.push(requested)
            return result()
        },
    }
}

function notConform(status: number): oauth.OperationProcessingError {
    return new oauth.OperationProcessingError("not conform", {
        code: oauth.RESPONSE_IS_NOT_CONFORM,
        cause: new Response(null, {status}),
    })
}

describe("FallbackAuthorizationServerProvider", () => {
    it("does not use the fallback on success", async () => {
        const fallbackCalls: URL[] = []
        const provider = new FallbackAuthorizationServerProvider(
            createProvider(async () => primaryServer),
            createProvider(async () => fallbackServer, fallbackCalls),
        )

        const server = await provider.getAuthorizationServer(issuer, new AbortController().signal)

        assert.equal(server, primaryServer)
        assert.equal(fallbackCalls.length, 0)
    })

    it("uses the fallback on 404", async () => {
        const fallbackCalls: URL[] = []
        const provider = new FallbackAuthorizationServerProvider(
            createProvider(async () => { throw notConform(404) }),
            createProvider(async () => fallbackServer, fallbackCalls),
        )

        const server = await provider.getAuthorizationServer(issuer, new AbortController().signal)

        assert.equal(server, fallbackServer)
        assert.deepEqual(fallbackCalls, [issuer])
    })

    it("passes the signal to the fallback", async () => {
        let received: AbortSignal | undefined
        const signal = new AbortController().signal
        const provider = new FallbackAuthorizationServerProvider(
            createProvider(async () => { throw notConform(404) }),
            {getAuthorizationServer: async (_, s) => { received = s; return fallbackServer }},
        )

        await provider.getAuthorizationServer(issuer, signal)

        assert.equal(received, signal)
    })

    it("rethrows a 500", async () => {
        const fallbackCalls: URL[] = []
        const error = notConform(500)
        const provider = new FallbackAuthorizationServerProvider(
            createProvider(async () => { throw error }),
            createProvider(async () => fallbackServer, fallbackCalls),
        )

        await assert.rejects(provider.getAuthorizationServer(issuer, new AbortController().signal), (thrown: unknown) => thrown === error)
        assert.equal(fallbackCalls.length, 0)
    })

    it("rethrows other errors", async () => {
        const fallbackCalls: URL[] = []
        const error = new TypeError("network")
        const provider = new FallbackAuthorizationServerProvider(
            createProvider(async () => { throw error }),
            createProvider(async () => fallbackServer, fallbackCalls),
        )

        await assert.rejects(provider.getAuthorizationServer(issuer, new AbortController().signal), (thrown: unknown) => thrown === error)
        assert.equal(fallbackCalls.length, 0)
    })

    it("rethrows an error from the fallback", async () => {
        const error = new TypeError("fallback failed")
        const provider = new FallbackAuthorizationServerProvider(
            createProvider(async () => { throw notConform(404) }),
            createProvider(async () => { throw error }),
        )

        await assert.rejects(provider.getAuthorizationServer(issuer, new AbortController().signal), (thrown: unknown) => thrown === error)
    })
})
