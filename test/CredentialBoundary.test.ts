import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { CredentialBoundary, originOf } from "../src/CredentialBoundary.js"
import { ReactiveFetchManager } from "../src/ReactiveFetchManager.js"
import { ReactiveAuthenticationClient } from "../src/ReactiveAuthenticationClient.js"
import type { TokenProvider } from "../src/TokenProvider.js"

/**
 * A provider that matches everything and records every request it is asked to
 * upgrade — standing in for a real token provider so the tests can assert
 * whether the reactive layer would have attached credentials to a given origin.
 */
function recordingProvider(): {provider: TokenProvider; upgraded: Request[]} {
    const upgraded: Request[] = []
    const provider: TokenProvider = {
        matches: async () => true,
        upgrade: async request => {
            upgraded.push(request)
            const headers = new Headers(request.headers)
            headers.set("Authorization", "DPoP secret-access-token")
            return new Request(request, {headers})
        },
    }
    return {provider, upgraded}
}

describe("originOf", () => {
    it("reduces a URL to its canonical origin", () => {
        expect(originOf("https://pod.example/a/b?x=1")).toBe("https://pod.example")
        expect(originOf("https://pod.example:443/a")).toBe("https://pod.example")
        expect(originOf(new URL("https://pod.example:8443/a"))).toBe("https://pod.example:8443")
    })

    it("returns undefined for a non-absolute URL", () => {
        expect(originOf("/relative/path")).toBeUndefined()
        expect(originOf("not a url")).toBeUndefined()
    })
})

describe("CredentialBoundary", () => {
    it("trusts exactly the configured origins", () => {
        const boundary = new CredentialBoundary(["https://pod.example", new URL("https://other.example/ignored/path")])
        expect(boundary.allows("https://pod.example")).toBe(true)
        expect(boundary.allows("https://other.example")).toBe(true)
        expect(boundary.allows("https://untrusted.example")).toBe(false)
    })

    it("does not trust a look-alike host (origin, not substring, comparison)", () => {
        const boundary = new CredentialBoundary(["https://pod.example"])
        expect(boundary.allows("https://pod.example.attacker.test")).toBe(false)
        expect(boundary.allows("http://pod.example")).toBe(false) // scheme differs
    })

    it("supports origin predicates", () => {
        const boundary = new CredentialBoundary([origin => origin.endsWith(".trusted.example")])
        expect(boundary.allows("https://a.trusted.example")).toBe(true)
        expect(boundary.allows("https://b.other.example")).toBe(false)
    })

    it("widens in place via add() without narrowing", () => {
        const boundary = new CredentialBoundary(["https://pod.example"])
        expect(boundary.allows("https://shared.example")).toBe(false)
        boundary.add("https://shared.example")
        expect(boundary.allows("https://pod.example")).toBe(true)
        expect(boundary.allows("https://shared.example")).toBe(true)
    })
})

describe("ReactiveFetchManager credential boundary", () => {
    let unauthorized: () => Response

    beforeEach(() => {
        unauthorized = () => new Response(null, {status: 401})
    })

    afterEach(() => {
        vi.restoreAllMocks()
        vi.unstubAllGlobals()
    })

    it("does not upgrade — nor leak credentials to — an out-of-boundary origin", async () => {
        vi.stubGlobal("fetch", vi.fn(async () => unauthorized()))
        const {provider, upgraded} = recordingProvider()
        const manager = new ReactiveFetchManager([provider], {allowedOrigins: ["https://pod.example"]})

        const response = await manager.fetch("https://tracker.attacker.test/pixel")

        expect(response.status).toBe(401)
        expect(upgraded).toHaveLength(0) // provider.upgrade never called → no credentials minted
    })

    it("upgrades an in-boundary origin", async () => {
        const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
            const request = new Request(input)
            // The retry (which carries credentials) succeeds; the first attempt is 401.
            return request.headers.get("Authorization") === null ? unauthorized() : new Response("ok")
        })
        vi.stubGlobal("fetch", fetchMock)
        const {provider, upgraded} = recordingProvider()
        const manager = new ReactiveFetchManager([provider], {allowedOrigins: ["https://pod.example"]})

        const response = await manager.fetch("https://pod.example/private")

        expect(response.status).toBe(200)
        expect(upgraded).toHaveLength(1)
        expect(upgraded[0]!.url).toBe("https://pod.example/private")
    })

    it("honours a boundary widened after construction (reArm)", async () => {
        const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
            const request = new Request(input)
            return request.headers.get("Authorization") === null ? unauthorized() : new Response("ok")
        })
        vi.stubGlobal("fetch", fetchMock)
        const {provider, upgraded} = recordingProvider()
        const boundary = new CredentialBoundary(["https://pod.example"])
        const manager = new ReactiveFetchManager([provider], {allowedOrigins: boundary})

        // Before widening: not upgraded.
        expect((await manager.fetch("https://shared.example/x")).status).toBe(401)
        expect(upgraded).toHaveLength(0)

        boundary.add("https://shared.example")

        // After widening: upgraded, no re-construction required.
        expect((await manager.fetch("https://shared.example/x")).status).toBe(200)
        expect(upgraded).toHaveLength(1)
    })

    it("warns once and preserves legacy upgrade-everything behaviour when no boundary is set", async () => {
        const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
            const request = new Request(input)
            return request.headers.get("Authorization") === null ? unauthorized() : new Response("ok")
        })
        vi.stubGlobal("fetch", fetchMock)
        const warn = vi.spyOn(console, "warn").mockImplementation(() => {})
        const {provider, upgraded} = recordingProvider()
        const manager = new ReactiveFetchManager([provider])

        expect((await manager.fetch("https://any.example/x")).status).toBe(200)
        expect((await manager.fetch("https://another.example/y")).status).toBe(200)

        expect(upgraded).toHaveLength(2) // legacy: every 401 upgraded
        expect(warn).toHaveBeenCalledTimes(1) // but the operator is warned exactly once
    })
})

describe("ReactiveAuthenticationClient credential boundary", () => {
    afterEach(() => vi.restoreAllMocks())

    it("does not upgrade an out-of-boundary origin", async () => {
        const baseFetch = vi.fn(async () => new Response(null, {status: 401}))
        const {provider, upgraded} = recordingProvider()
        const client = new ReactiveAuthenticationClient(baseFetch, [provider], {
            allowedOrigins: ["https://pod.example"],
        })

        const response = await client.fetch(new Request("https://tracker.attacker.test/pixel"))

        expect(response.status).toBe(401)
        expect(upgraded).toHaveLength(0)
    })
})
