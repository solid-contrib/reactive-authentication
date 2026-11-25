import assert from "node:assert/strict"
import {describe, it} from "node:test"
import * as oauth from "oauth4webapi"
import {LwsTokenExchangeTargetProvider} from "../../src/lws/LwsTokenExchangeTargetProvider.js"
import type {StorageRootProvider} from "../../src/lws/storageDescription.js"
import {ReactiveAuthenticationError} from "../../src/ReactiveAuthenticationError.js"

const requested = "https://storage.example/storage_1/photos/img.jpg"
const metadataUrl = "https://storage.example/.well-known/oauth-protected-resource/storage_1/photos/img.jpg"
const storage = "https://storage.example/storage_1"
const issuer = "https://authorization.example"

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

const legacy = (realm: string) => unauthorized({"WWW-Authenticate": `Bearer realm="${realm}", as_uri="${issuer}"`})

function setup(metadataResource = requested) {
    const fetched: string[] = []
    const options = {
        [oauth.customFetch]: async (url: string) => {
            fetched.push(url)
            assert.equal(url, metadataUrl)
            return Response.json({resource: metadataResource, authorization_servers: [issuer]})
        },
    }
    const storageRootProvider: StorageRootProvider = {getStorageRoot: async () => storage}

    return {provider: new LwsTokenExchangeTargetProvider(storageRootProvider, options), fetched}
}

const request = (url = requested) => new Request(url)
const signal = new AbortController().signal

describe("LwsTokenExchangeTargetProvider", () => {
    describe("matches", () => {
        it("matches a challenge with resource_metadata", () => {
            assert.equal(setup().provider.matches(request(), unauthorized()), true)
        })

        it("matches a legacy challenge when the request is within the realm", () => {
            assert.equal(setup().provider.matches(request(), legacy(storage)), true)
        })

        it("does not match a legacy challenge when the request is outside the realm", () => {
            assert.equal(setup().provider.matches(request(), legacy("https://storage.example/storage_2")), false)
        })

        it("does not match a Basic challenge", () => {
            assert.equal(setup().provider.matches(request(), unauthorized({"WWW-Authenticate": "Basic realm=\"x\""})), false)
        })

        it("makes no network request", () => {
            const {provider, fetched} = setup()

            provider.matches(request(), unauthorized())

            assert.equal(fetched.length, 0)
        })
    })

    describe("getTarget", () => {
        it("discovers the issuer and the storage from resource_metadata", async () => {
            const {provider} = setup()

            assert.deepEqual(await provider.getTarget(request(), unauthorized(), signal), {issuer, resource: storage})
        })

        it("uses the realm as the resource and as_uri as the issuer for a legacy challenge", async () => {
            const {provider, fetched} = setup()

            assert.deepEqual(await provider.getTarget(request(), legacy(storage), signal), {issuer, resource: storage})
            assert.equal(fetched.length, 0)
        })

        it("throws when the response has neither challenge", async () => {
            const {provider} = setup()

            await assert.rejects(provider.getTarget(request(), legacy("https://storage.example/storage_2"), signal), ReactiveAuthenticationError)
        })

        it("does not downgrade to the legacy challenge when the current discovery fails", async () => {
            const {provider} = setup("https://storage.example/other")
            const response = unauthorized({"WWW-Authenticate": `Bearer resource_metadata="${metadataUrl}", realm="${storage}", as_uri="${issuer}"`})

            await assert.rejects(provider.getTarget(request(), response, signal), ReactiveAuthenticationError)
        })
    })
})
