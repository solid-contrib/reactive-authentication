import assert from "node:assert/strict"
import {afterEach, beforeEach, describe, it} from "node:test"
import {parseChallenges} from "../src/parseChallenges.js"
import {ReactiveFetchManager} from "../src/ReactiveFetchManager.js"
import type {TokenProvider} from "../src/TokenProvider.js"

describe("ReactiveFetchManager", () => {
    const originalFetch = globalThis.fetch

    beforeEach(() => {
        let calls = 0
        globalThis.fetch = async () => calls++ === 0
            ? new Response(null, {
                status: 401,
                headers: {
                    "WWW-Authenticate": 'Bearer realm="https://storage.example", as_uri="https://as.example"',
                    "Link": '<https://storage.example/>; rel="https://www.w3.org/ns/lws#storage"',
                },
            })
            : new Response(null, {status: 200})
    })

    afterEach(() => {
        globalThis.fetch = originalFetch
    })

    it("passes the 401 response to matches and upgrade", async () => {
        let matched: Response | undefined
        let upgraded: Response | undefined
        const provider: TokenProvider = {
            matches: async (_request, response) => {
                matched = response
                return true
            },
            upgrade: async (request, response) => {
                upgraded = response
                return request
            },
        }

        await new ReactiveFetchManager([provider]).fetch("https://storage.example/resource")

        for (const response of [matched, upgraded]) {
            assert.equal(response?.status, 401)
            assert.deepEqual(parseChallenges(response.headers.get("WWW-Authenticate")), [{
                scheme: "bearer",
                parameters: {realm: "https://storage.example", as_uri: "https://as.example"},
            }])
            assert.equal(response.headers.get("Link"), '<https://storage.example/>; rel="https://www.w3.org/ns/lws#storage"')
        }
    })
})
