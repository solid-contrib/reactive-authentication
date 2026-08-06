import "fake-indexeddb/auto"
import { beforeEach, describe, expect, it, vi } from "vitest"
import { DPoPTokenProvider, type DPoPSession } from "../src/DPoPTokenProvider.js"
import { IndexedDbSessionCache } from "../src/IndexedDbSessionCache.js"
import { WebStorageSessionCache } from "../src/WebStorageSessionCache.js"
import { MemorySessionCache } from "../src/MemorySessionCache.js"
import type { SessionCache } from "../src/SessionCache.js"
import { createFakeAuthorizationServer, type FakeAuthorizationServer } from "./fakeAuthorizationServer.js"

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

describe.each([
    ["MemorySessionCache", () => new MemorySessionCache<unknown>()],
    ["WebStorageSessionCache", () => new WebStorageSessionCache<unknown>(memoryStorage())],
    ["IndexedDbSessionCache", () => new IndexedDbSessionCache<unknown>(`db-${Math.random()}`)],
])("%s", (_, create) => {
    let cache: SessionCache<unknown>

    beforeEach(() => {
        cache = create()
    })

    it("round trips a value", async () => {
        await cache.set("k", {accessToken: "at-1"})

        expect(await cache.get("k")).toEqual({accessToken: "at-1"})
    })

    it("reports a missing key as undefined", async () => {
        expect(await cache.get("absent")).toBeUndefined()
    })

    it("forgets a deleted key", async () => {
        await cache.set("k", {accessToken: "at-1"})
        await cache.delete("k")

        expect(await cache.get("k")).toBeUndefined()
    })
})

describe("WebStorageSessionCache", () => {
    it("refuses a CryptoKey rather than silently storing an empty object", async () => {
        const cache = new WebStorageSessionCache<unknown>(memoryStorage())
        const dpopKey = await crypto.subtle.generateKey({name: "ECDSA", namedCurve: "P-256"}, false, ["sign", "verify"])

        await expect(cache.set("k", {dpopKey})).rejects.toThrow(/CryptoKey cannot be stored/)
    })

    it("namespaces its keys", async () => {
        const storage = memoryStorage()
        await new WebStorageSessionCache<unknown>(storage).set("https://as.test/", "x")

        expect(storage.key(0)).toBe("reactive-authentication:https://as.test/")
    })

    it("discards an unparseable entry", async () => {
        const storage = memoryStorage()
        storage.setItem("reactive-authentication:k", "not json")

        expect(await new WebStorageSessionCache<unknown>(storage).get("k")).toBeUndefined()
    })
})

describe("IndexedDbSessionCache", () => {
    it("keeps a non extractable CryptoKeyPair usable across a round trip", async () => {
        const cache = new IndexedDbSessionCache<{dpopKey: CryptoKeyPair}>(`db-${Math.random()}`)
        const dpopKey = await crypto.subtle.generateKey({name: "ECDSA", namedCurve: "P-256"}, false, ["sign", "verify"])

        await cache.set("k", {dpopKey})
        const restored = (await cache.get("k"))!.dpopKey

        expect(restored.privateKey).toBeInstanceOf(CryptoKey)
        expect(restored.privateKey.extractable).toBe(false)
        expect(await crypto.subtle.sign({name: "ECDSA", hash: "SHA-256"}, restored.privateKey, new Uint8Array([1]))).toBeInstanceOf(ArrayBuffer)
    })

    it("carries a DPoP session across a simulated reload, so the user is not prompted again", async () => {
        const as: FakeAuthorizationServer = await createFakeAuthorizationServer()
        vi.stubGlobal("fetch", as.fetch)

        const databaseName = `db-${Math.random()}`
        const before = new DPoPTokenProvider(callbackUri, url => as.authorize(url), async () => new URL(as.issuer), {
            sessionCache: new IndexedDbSessionCache<DPoPSession>(databaseName),
        })
        const first = await before.upgrade(new Request("https://pod.test/a"))

        // A new provider over the same database stands in for the page being reloaded.
        const getCode = vi.fn((url: URL) => as.authorize(url))
        const after = new DPoPTokenProvider(callbackUri, getCode, async () => new URL(as.issuer), {
            sessionCache: new IndexedDbSessionCache<DPoPSession>(databaseName),
        })
        const second = await after.upgrade(new Request("https://pod.test/b"))

        expect(getCode).not.toHaveBeenCalled()
        expect(second.headers.get("Authorization")).toBe(first.headers.get("Authorization"))
        expect(second.headers.get("DPoP")).not.toBe(first.headers.get("DPoP"))

        vi.unstubAllGlobals()
    })
})
