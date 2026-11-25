import assert from "node:assert/strict"
import {describe, it} from "node:test"
import * as oauth from "oauth4webapi"
import {CachingStorageRootProvider, fetchStorageRoot, LwsStorageRootProvider} from "../src/storageDescription.js"
import {ReactiveAuthenticationError} from "../src/ReactiveAuthenticationError.js"

type Call = { url: string, init: RequestInit | undefined }

const storage = "https://storage.example/"
const signal = new AbortController().signal

function description(overrides: Record<string, unknown> = {}): Record<string, unknown> {
    return {
        "@context": ["https://www.w3.org/ns/cid/v1", "https://www.w3.org/ns/lws/v1"],
        id: storage,
        type: "Storage",
        service: [{type: "StorageRoot", serviceEndpoint: "https://storage.example/root/"}],
        ...overrides,
    }
}

function options(respond: () => Response, calls: Call[] = []): oauth.HttpRequestOptions<string, any> {
    return {
        [oauth.customFetch]: async (url: string, init?: RequestInit) => {
            calls.push({url, init})
            return respond()
        },
    }
}

const json = (body: unknown, status = 200) => () => Response.json(body, {status})

describe("fetchStorageRoot", () => {
    it("reads the StorageRoot service endpoint", async () => {
        const root = await fetchStorageRoot(storage, signal, options(json(description())))

        assert.equal(root, "https://storage.example/root/")
    })

    it("selects the StorageRoot among other services", async () => {
        const body = description({
            service: [
                {type: "NotificationService", serviceEndpoint: "https://storage.example/notification/api"},
                {type: "StorageRoot", serviceEndpoint: "https://storage.example/root/"},
            ],
        })

        assert.equal(await fetchStorageRoot(storage, signal, options(json(body))), "https://storage.example/root/")
    })

    it("accepts a type that is an array", async () => {
        const body = description({service: [{type: ["Other", "StorageRoot"], serviceEndpoint: "https://storage.example/root/"}]})

        assert.equal(await fetchStorageRoot(storage, signal, options(json(body))), "https://storage.example/root/")
    })

    it("requests application/cid", async () => {
        const calls: Call[] = []

        await fetchStorageRoot(storage, signal, options(json(description()), calls))

        assert.deepEqual(calls.map(call => call.url), [storage])
        assert.deepEqual(calls[0]!.init?.headers, {accept: "application/cid"})
        assert.equal(calls[0]!.init?.method, "GET")
    })

    it("throws on an unsuccessful response", async () => {
        await assert.rejects(
            fetchStorageRoot(storage, signal, options(json(description(), 404))),
            (error: unknown) => error instanceof ReactiveAuthenticationError && error.cause instanceof Response,
        )
    })

    it("throws on a response that is not JSON", async () => {
        await assert.rejects(
            fetchStorageRoot(storage, signal, options(() => new Response("<html>"))),
            ReactiveAuthenticationError,
        )
    })

    it("throws on a missing @context", async () => {
        const {"@context": _, ...body} = description()

        await assert.rejects(fetchStorageRoot(storage, signal, options(json(body))), ReactiveAuthenticationError)
    })

    for (const [name, context] of [
        ["a string", "https://www.w3.org/ns/cid/v1"],
        ["missing the LWS context", ["https://www.w3.org/ns/cid/v1"]],
        ["in the wrong order", ["https://www.w3.org/ns/lws/v1", "https://www.w3.org/ns/cid/v1"]],
        ["a different context", ["https://www.w3.org/ns/cid/v1", "https://other.example/v1"]],
    ] as const) {
        it(`throws on an @context that is ${name}`, async () => {
            await assert.rejects(fetchStorageRoot(storage, signal, options(json(description({"@context": context})))), ReactiveAuthenticationError)
        })
    }

    it("throws when there is no StorageRoot service", async () => {
        const body = description({service: [{type: "NotificationService", serviceEndpoint: "https://storage.example/n"}]})

        await assert.rejects(fetchStorageRoot(storage, signal, options(json(body))), ReactiveAuthenticationError)
    })

    it("throws when there is no service", async () => {
        const {service: _, ...body} = description()

        await assert.rejects(fetchStorageRoot(storage, signal, options(json(body))), ReactiveAuthenticationError)
    })

    it("throws when the serviceEndpoint is not a string", async () => {
        const body = description({service: [{type: "StorageRoot", serviceEndpoint: ["https://storage.example/root/"]}]})

        await assert.rejects(fetchStorageRoot(storage, signal, options(json(body))), ReactiveAuthenticationError)
    })

    it("rejects an HTTP storage URI unless insecure requests are allowed", async () => {
        const calls: Call[] = []

        await assert.rejects(fetchStorageRoot("http://storage.example/", signal, options(json(description()), calls)))
        assert.equal(calls.length, 0)

        await fetchStorageRoot("http://storage.example/", signal, {...options(json(description()), calls), [oauth.allowInsecureRequests]: true})
        assert.equal(calls.length, 1)
    })
})

describe("CachingStorageRootProvider", () => {
    it("requests the storage description once", async () => {
        const calls: Call[] = []
        const provider = new CachingStorageRootProvider(new LwsStorageRootProvider(options(json(description()), calls)))

        const first = await provider.getStorageRoot(storage, signal)
        const second = await provider.getStorageRoot(storage, signal)

        assert.equal(first, "https://storage.example/root/")
        assert.equal(second, first)
        assert.equal(calls.length, 1)
    })

    it("does not cache a failure", async () => {
        const calls: Call[] = []
        let status = 500
        const provider = new CachingStorageRootProvider(new LwsStorageRootProvider(options(() => Response.json(description(), {status}), calls)))

        await assert.rejects(provider.getStorageRoot(storage, signal))
        status = 200

        assert.equal(await provider.getStorageRoot(storage, signal), "https://storage.example/root/")
        assert.equal(calls.length, 2)
    })
})
