import "fake-indexeddb/auto"
import assert from "node:assert/strict"
import { beforeEach, describe, it } from "node:test"
import { DPoPTokenProvider, type DPoPSession } from "../dist/DPoPTokenProvider.js"
import { IndexedDbSessionCache } from "../dist/IndexedDbSessionCache.js"
import { WebStorageSessionCache } from "../dist/WebStorageSessionCache.js"
import { MemorySessionCache } from "../dist/MemorySessionCache.js"
import type { SessionCache } from "../dist/SessionCache.js"
import { createFakeAuthorizationServer } from "./fakeAuthorizationServer.ts"

const callbackUri = "https://app.test/callback.html"

function memoryStorage(): Storage {
    const entries = new Map<string, string>()

    return {
        getItem: key => entries.get(key) ?? null,
        setItem: (key, value) => void entries.set(key, String(value)),
        removeItem: key => void entries.delete(key),
        clear: () => entries.clear(),
        key: index => [...entries.keys()][index] ?? null,
        get length() {
            return entries.size
        },
    } as Storage
}

const caches = [
    ["MemorySessionCache", () => new MemorySessionCache<unknown>()],
    ["WebStorageSessionCache", () => new WebStorageSessionCache<unknown>(memoryStorage())],
    ["IndexedDbSessionCache", () => new IndexedDbSessionCache<unknown>(`db-${Math.random()}`)],
] as const

for (const [name, create] of caches) {
    describe(name, () => {
        let cache: SessionCache<unknown>

        beforeEach(() => {
            cache = create()
        })

        it("round trips a value", async () => {
            await cache.set("k", {accessToken: "at-1"})

            assert.deepEqual(await cache.get("k"), {accessToken: "at-1"})
        })

        it("reports a missing key as undefined", async () => {
            assert.equal(await cache.get("absent"), undefined)
        })

        it("forgets a deleted key", async () => {
            await cache.set("k", {accessToken: "at-1"})
            await cache.delete("k")

            assert.equal(await cache.get("k"), undefined)
        })
    })
}

describe("WebStorageSessionCache", () => {
    it("refuses a CryptoKey rather than silently storing an empty object", async () => {
        const cache = new WebStorageSessionCache<unknown>(memoryStorage())
        const dpopKey = await crypto.subtle.generateKey({name: "ECDSA", namedCurve: "P-256"}, false, ["sign", "verify"])

        await assert.rejects(cache.set("k", {dpopKey}), /CryptoKey cannot be stored/)
    })

    it("namespaces its keys", async () => {
        const storage = memoryStorage()
        await new WebStorageSessionCache<unknown>(storage).set("https://as.test/", "x")

        assert.equal(storage.key(0), "reactive-authentication:https://as.test/")
    })

    it("discards an unparseable entry", async () => {
        const storage = memoryStorage()
        storage.setItem("reactive-authentication:k", "not json")

        assert.equal(await new WebStorageSessionCache<unknown>(storage).get("k"), undefined)
    })
})

describe("IndexedDbSessionCache", () => {
    it("keeps a non extractable CryptoKeyPair usable across a round trip", async () => {
        const cache = new IndexedDbSessionCache<{dpopKey: CryptoKeyPair}>(`db-${Math.random()}`)
        const dpopKey = await crypto.subtle.generateKey({name: "ECDSA", namedCurve: "P-256"}, false, ["sign", "verify"])

        await cache.set("k", {dpopKey})
        const restored = (await cache.get("k"))!.dpopKey

        assert.ok(restored.privateKey instanceof CryptoKey)
        assert.equal(restored.privateKey.extractable, false)
        assert.ok(await crypto.subtle.sign({name: "ECDSA", hash: "SHA-256"}, restored.privateKey, new Uint8Array([1])) instanceof ArrayBuffer)
    })

    it("carries a DPoP session across a simulated reload, so the user is not prompted again", async t => {
        const as = await createFakeAuthorizationServer()
        t.mock.method(globalThis, "fetch", as.fetch)

        try {
            const databaseName = `db-${Math.random()}`
            const before = new DPoPTokenProvider(callbackUri, url => as.authorize(url), async () => new URL(as.issuer), {
                sessionCache: new IndexedDbSessionCache<DPoPSession>(databaseName),
            })
            const first = await before.upgrade(new Request("https://pod.test/a"))

            const getCode = t.mock.fn((url: URL) => as.authorize(url))
            const after = new DPoPTokenProvider(callbackUri, getCode, async () => new URL(as.issuer), {
                sessionCache: new IndexedDbSessionCache<DPoPSession>(databaseName),
            })
            const second = await after.upgrade(new Request("https://pod.test/b"))

            assert.equal(getCode.mock.callCount(), 0)
            assert.equal(second.headers.get("Authorization"), first.headers.get("Authorization"))
            assert.notEqual(second.headers.get("DPoP"), first.headers.get("DPoP"))
        } finally {
            await as.close()
        }
    })
})
