import assert from "node:assert/strict"
import {describe, it} from "node:test"
import * as oauth from "oauth4webapi"
import {LwsDiscoveryAuthorizationServerProvider} from "../../src/lws/LwsDiscoveryAuthorizationServerProvider.js"

type Call = { url: string, init: RequestInit | undefined }

function createProvider(respond: (url: string) => Response, calls: Call[] = []): LwsDiscoveryAuthorizationServerProvider {
    return new LwsDiscoveryAuthorizationServerProvider({
        [oauth.customFetch]: async (url: string, init?: RequestInit) => {
            calls.push({url, init})
            return respond(url)
        },
    })
}

function metadata(issuer: string, status = 200): Response {
    return Response.json({issuer}, {status})
}

describe("LwsDiscoveryAuthorizationServerProvider", () => {
    it("requests the lws-configuration path", async () => {
        const calls: Call[] = []
        const provider = createProvider(() => metadata("https://as.example"), calls)

        const server = await provider.getAuthorizationServer(new URL("https://as.example"), new AbortController().signal)

        assert.equal(server.issuer, "https://as.example")
        assert.deepEqual(calls.map(call => call.url), ["https://as.example/.well-known/lws-configuration"])
    })

    it("inserts the well-known path before the issuer path", async () => {
        const calls: Call[] = []
        const provider = createProvider(() => metadata("https://as.example/tenant"), calls)

        await provider.getAuthorizationServer(new URL("https://as.example/tenant"), new AbortController().signal)

        assert.deepEqual(calls.map(call => call.url), ["https://as.example/.well-known/lws-configuration/tenant"])
    })

    it("throws an error that exposes the 404 response", async () => {
        const provider = createProvider(() => new Response(null, {status: 404}))

        await assert.rejects(provider.getAuthorizationServer(new URL("https://as.example"), new AbortController().signal), (error: unknown) => {
            assert.ok(error instanceof oauth.OperationProcessingError)
            assert.equal(error.code, oauth.RESPONSE_IS_NOT_CONFORM)
            assert.ok(error.cause instanceof Response)
            assert.equal(error.cause.status, 404)
            return true
        })
    })

    it("makes a single request on errors", async () => {
        const calls: Call[] = []
        const provider = createProvider(() => new Response(null, {status: 500}), calls)

        await assert.rejects(provider.getAuthorizationServer(new URL("https://as.example"), new AbortController().signal))

        assert.equal(calls.length, 1)
    })

    it("rejects an issuer mismatch", async () => {
        const provider = createProvider(() => metadata("https://other.example"))

        await assert.rejects(provider.getAuthorizationServer(new URL("https://as.example"), new AbortController().signal))
    })

    it("accepts an issuer without a trailing slash", async () => {
        const issuer = "https://platform.odi.ess.solid-experiments.org"
        const provider = createProvider(() => metadata(issuer))

        const server = await provider.getAuthorizationServer(new URL(issuer), new AbortController().signal)

        assert.equal(server.issuer, issuer)
    })

    it("passes the signal and accept header", async () => {
        const calls: Call[] = []
        const provider = createProvider(() => metadata("https://as.example"), calls)
        const signal = new AbortController().signal

        await provider.getAuthorizationServer(new URL("https://as.example"), signal)

        assert.equal(calls[0]?.init?.signal, signal)
        assert.deepEqual(calls[0]?.init?.headers, {accept: "application/json"})
    })

    it("rejects non-https issuers unless allowed", async () => {
        const calls: Call[] = []
        const provider = createProvider(() => metadata("http://as.example"), calls)

        await assert.rejects(provider.getAuthorizationServer(new URL("http://as.example"), new AbortController().signal))
        assert.equal(calls.length, 0)
    })
})
