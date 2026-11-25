import assert from "node:assert/strict"
import {describe, it} from "node:test"
import * as oauth from "oauth4webapi"
import {discoverProtectedResource} from "../../src/lws/protectedResourceDiscovery.js"
import type {StorageRootProvider} from "../../src/lws/storageDescription.js"
import {ReactiveAuthenticationError} from "../../src/ReactiveAuthenticationError.js"

type Call = { url: string, init: RequestInit | undefined }

const requested = "https://storage.example/storage_1/photos/img.jpg"
const metadataUrl = "https://storage.example/.well-known/oauth-protected-resource/storage_1/photos/img.jpg"
const storage = "https://storage.example/storage_1"
const signal = new AbortController().signal

function unauthorized(headers: Record<string, string> = {}, url = requested): Response {
    const response = new Response(null, {
        status: 401,
        headers: {
            "WWW-Authenticate": `Bearer resource_metadata="${metadataUrl}", error="invalid_token"`,
            "Link": `<${storage}>; rel="https://www.w3.org/ns/lws#storage"`,
            ...headers,
        },
    })
    Object.defineProperty(response, "url", {value: url})
    return response
}

function options(respond: () => Response, calls: Call[] = []): oauth.HttpRequestOptions<string, any> {
    return {
        [oauth.customFetch]: async (url: string, init?: RequestInit) => {
            calls.push({url, init})
            return respond()
        },
    }
}

const noFetch = () => assert.fail("must not fetch")

const metadata = (body: Record<string, unknown> = {}) => () => Response.json({
    resource: requested,
    authorization_servers: ["https://authorization.example", "https://other.example"],
    ...body,
})

const roots = (root: string): StorageRootProvider => ({getStorageRoot: async () => root})

const rejects = (promise: Promise<unknown>) => assert.rejects(promise, ReactiveAuthenticationError)

describe("discoverProtectedResource", () => {
    it("returns the first authorization server and the storage", async () => {
        const calls: Call[] = []

        const result = await discoverProtectedResource(unauthorized(), roots("https://storage.example/storage_1/"), signal, options(metadata(), calls))

        assert.deepEqual(result, {issuer: "https://authorization.example", resource: storage})
        assert.equal(calls.length, 1)
        assert.equal(calls[0]?.url, metadataUrl)
        assert.equal(calls[0]?.init?.redirect, "manual")
    })

    it("accepts a DPoP challenge", async () => {
        const response = unauthorized({"WWW-Authenticate": `DPoP resource_metadata="${metadataUrl}", algs="ES256"`})

        const result = await discoverProtectedResource(response, roots(storage), signal, options(metadata()))

        assert.equal(result?.issuer, "https://authorization.example")
    })

    it("returns undefined without resource_metadata", async () => {
        const response = unauthorized({"WWW-Authenticate": 'Bearer error="invalid_token"'})

        assert.equal(await discoverProtectedResource(response, roots(storage), signal, options(noFetch)), undefined)
    })

    it("returns undefined for a legacy challenge", async () => {
        const response = unauthorized({"WWW-Authenticate": 'Bearer as_uri="https://authorization.example", realm="https://storage.example/storage_1"'})

        assert.equal(await discoverProtectedResource(response, roots(storage), signal, options(noFetch)), undefined)
    })

    it("rejects a resource_metadata of another origin", async () => {
        const response = unauthorized({"WWW-Authenticate": 'Bearer resource_metadata="https://evil.example/metadata"'})

        await rejects(discoverProtectedResource(response, roots(storage), signal, options(noFetch)))
    })

    it("rejects a resource_metadata with another port", async () => {
        const response = unauthorized({"WWW-Authenticate": 'Bearer resource_metadata="https://storage.example:8443/metadata"'})

        await rejects(discoverProtectedResource(response, roots(storage), signal, options(noFetch)))
    })

    it("rejects a resource that is not identical to the requested URI", async () => {
        await rejects(discoverProtectedResource(unauthorized(), roots(storage), signal, options(metadata({resource: "https://storage.example/storage_1/other"}))))
    })

    it("rejects a resource that is identical only after normalization", async () => {
        await rejects(discoverProtectedResource(unauthorized(), roots(storage), signal, options(metadata({resource: "https://STORAGE.example/storage_1/photos/img.jpg"}))))
    })

    it("rejects a storage root of another origin", async () => {
        await rejects(discoverProtectedResource(unauthorized(), roots("https://evil.example/storage_1/"), signal, options(metadata())))
    })

    it("rejects a storage root that is not a URL", async () => {
        await rejects(discoverProtectedResource(unauthorized(), roots("not a url"), signal, options(metadata())))
    })

    it("rejects missing authorization_servers", async () => {
        await rejects(discoverProtectedResource(unauthorized(), roots(storage), signal, options(metadata({authorization_servers: undefined}))))
    })

    it("rejects empty authorization_servers", async () => {
        await rejects(discoverProtectedResource(unauthorized(), roots(storage), signal, options(metadata({authorization_servers: []}))))
    })

    it("rejects authorization_servers with a non-string entry", async () => {
        await rejects(discoverProtectedResource(unauthorized(), roots(storage), signal, options(metadata({authorization_servers: [1]}))))
    })

    it("rejects a missing storage link", async () => {
        const response = unauthorized()
        response.headers.delete("Link")

        await rejects(discoverProtectedResource(response, roots(storage), signal, options(metadata())))
    })

    it("rejects an unsuccessful metadata response", async () => {
        await rejects(discoverProtectedResource(unauthorized(), roots(storage), signal, options(() => new Response(null, {status: 404}))))
    })

    it("rejects a failed metadata request", async () => {
        await rejects(discoverProtectedResource(unauthorized(), roots(storage), signal, {
            [oauth.customFetch]: async () => {
                throw new TypeError("network")
            },
        }))
    })

    it("rejects an insecure metadata URL unless allowed", async () => {
        const url = "http://storage.example/storage_1/photos/img.jpg"
        const response = unauthorized({
            "WWW-Authenticate": 'Bearer resource_metadata="http://storage.example/metadata"',
            "Link": '<http://storage.example/storage_1>; rel="https://www.w3.org/ns/lws#storage"',
        }, url)
        const respond = metadata({resource: url, authorization_servers: ["https://authorization.example"]})

        await assert.rejects(discoverProtectedResource(response, roots("http://storage.example/"), signal, options(respond)))

        const allowed = {...options(respond), [oauth.allowInsecureRequests]: true} as oauth.HttpRequestOptions<string, any>
        const result = await discoverProtectedResource(response, roots("http://storage.example/"), signal, allowed)
        assert.equal(result?.resource, "http://storage.example/storage_1")
    })
})
