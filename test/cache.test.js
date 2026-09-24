import assert from "node:assert/strict"
import { test } from "node:test"
import { IDBFactory } from "fake-indexeddb"
import { MemoryCache } from "../dist/MemoryCache.js"
import { IndexedDbCache } from "../dist/IndexedDbCache.js"
import { WebStorageCache } from "../dist/WebStorageCache.js"
import { ExpiringCache } from "../dist/ExpiringCache.js"
import { createBrowserCaches } from "../dist/createBrowserCaches.js"

class TestStorage {
    values = new Map()
    get length() { return this.values.size }
    key(index) { return [...this.values.keys()][index] ?? null }
    getItem(key) { return this.values.get(key) ?? null }
    setItem(key, value) { this.values.set(key, value) }
    removeItem(key) { this.values.delete(key) }
}
const codec = { encode: JSON.stringify, decode: JSON.parse }

for (const [name, create] of [
    ["memory", () => new MemoryCache()],
    ["IndexedDB", () => new IndexedDbCache("contract", new IDBFactory())],
    ["Web Storage", () => new WebStorageCache(new TestStorage(), "contract", codec)],
]) {
    test(`${name}: miss, overwrite, delete, clear, and falsy values`, async () => {
        const cache = create()
        assert.equal(await cache.get("missing"), undefined)
        for (const value of [false, 0, "", null, { issuer: "https://idp.example" }]) {
            await cache.set("key", value)
            assert.deepEqual(await cache.get("key"), value)
        }
        await cache.delete("key")
        await cache.delete("missing")
        assert.equal(await cache.get("key"), undefined)
        await cache.set("a", 1)
        await cache.set("b", 2)
        await cache.clear()
        assert.equal(await cache.get("a"), undefined)
        assert.equal(await cache.get("b"), undefined)
    })
}

test("persistent adapters survive reconstruction and clear only their namespace", async () => {
    const storage = new TestStorage()
    storage.setItem("unrelated", "keep")
    const factory = new IDBFactory()
    for (const create of [
        name => new WebStorageCache(storage, name, codec),
        name => new IndexedDbCache(name, factory),
    ]) {
        const first = create("app")
        const second = create("app:other")
        await first.set("key", "first")
        await second.set("key", "second")
        assert.equal(await create("app").get("key"), "first")
        await first.clear()
        assert.equal(await second.get("key"), "second")
    }
    assert.equal(storage.getItem("unrelated"), "keep")
})

test("IndexedDB preserves a non-extractable private key that still signs", async () => {
    const factory = new IDBFactory()
    const keys = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"])
    await new IndexedDbCache("keys", factory).set("key", keys)
    const restored = await new IndexedDbCache("keys", factory).get("key")
    assert.equal(restored.privateKey.extractable, false)
    await assert.rejects(crypto.subtle.exportKey("jwk", restored.privateKey))
    const data = new TextEncoder().encode("proof")
    const algorithm = { name: "ECDSA", hash: "SHA-256" }
    const signature = await crypto.subtle.sign(algorithm, restored.privateKey, data)
    assert.equal(await crypto.subtle.verify(algorithm, keys.publicKey, signature, data), true)
})

test("IndexedDB rejects uncloneable values without replacing existing entries", async () => {
    const cache = new IndexedDbCache("clone-errors", new IDBFactory())
    await cache.set("key", "original")
    await assert.rejects(cache.set("key", () => {}), { name: "DataCloneError" })
    assert.equal(await cache.get("key"), "original")
})

test("IndexedDB waits for commit and rejects a transaction aborted after request success", async () => {
    const factory = new IDBFactory()
    const open = factory.open.bind(factory)
    factory.open = (...args) => {
        const request = open(...args)
        request.addEventListener("success", () => {
            const database = request.result
            const transaction = database.transaction.bind(database)
            database.transaction = (...args) => {
                const tx = transaction(...args)
                if (args[1] === "readwrite") {
                    const objectStore = tx.objectStore.bind(tx)
                    tx.objectStore = name => {
                        const store = objectStore(name)
                        const put = store.put.bind(store)
                        store.put = (...args) => {
                            const write = put(...args)
                            write.addEventListener("success", () => tx.abort())
                            return write
                        }
                        return store
                    }
                }
                return tx
            }
        })
        return request
    }
    const cache = new IndexedDbCache("abort", factory)
    await assert.rejects(cache.set("key", "uncommitted"), /aborted/)
    assert.equal(await cache.get("key"), undefined)
})

test("storage denial and malformed encodings are surfaced", async () => {
    const denied = new DOMException("denied", "SecurityError")
    const cache = new WebStorageCache({ getItem() { throw denied }, setItem() { throw denied } }, "denied", codec)
    await assert.rejects(cache.get("a"), denied)
    await assert.rejects(cache.set("a", 1), denied)
    const storage = new TestStorage()
    const corrupt = new WebStorageCache(storage, "corrupt", { encode: () => "{", decode: JSON.parse })
    await corrupt.set("a", 1)
    await assert.rejects(corrupt.get("a"), SyntaxError)
    await assert.rejects(new IndexedDbCache("denied", { open() { throw denied } }).get("a"), denied)
})

test("TTL survives reconstruction, expires at the boundary, and does not delete newer data", async t => {
    t.mock.method(Date, "now", () => 1000)
    const backing = new MemoryCache()
    const cache = new ExpiringCache(backing, 100)
    await cache.set("a", "old")
    t.mock.method(Date, "now", () => 1099)
    assert.equal(await new ExpiringCache(backing, 100).get("a"), "old")
    t.mock.method(Date, "now", () => 1100)
    assert.equal(await cache.get("a"), undefined)
    assert.equal((await backing.get("a")).value, "old")
    await cache.set("a", "new")
    assert.equal(await cache.get("a"), "new")
    await cache.delete("a")
    assert.equal(await cache.get("a"), undefined)
    await cache.set("b", "new")
    await cache.clear()
    assert.equal(await cache.get("b"), undefined)
    for (const age of [0, -1, NaN, Infinity]) assert.throws(() => new ExpiringCache(backing, age), TypeError)
})

test("browser preset persists only metadata and expires it", async t => {
    const previous = Object.getOwnPropertyDescriptor(globalThis, "indexedDB")
    Object.defineProperty(globalThis, "indexedDB", { configurable: true, value: new IDBFactory() })
    t.after(() => {
        if (previous) Object.defineProperty(globalThis, "indexedDB", previous)
        else delete globalThis.indexedDB
    })
    t.mock.method(Date, "now", () => 1000)
    const caches = createBrowserCaches("my-app/account", 100)
    await caches.issuer.set("resource", "https://idp.example")
    await caches.authorizationServer.set("resource", { issuer: "https://idp.example" })
    await caches.client.set("issuer", { client_id: "private-client" })
    await caches.token.set("resource", { secret: "memory only" })
    const restored = createBrowserCaches("my-app/account", 100)
    assert.equal(await restored.issuer.get("resource"), "https://idp.example")
    assert.deepEqual(await restored.authorizationServer.get("resource"), { issuer: "https://idp.example" })
    assert.equal(await restored.client.get("issuer"), undefined)
    assert.equal(await restored.token.get("resource"), undefined)
    t.mock.method(Date, "now", () => 1100)
    assert.equal(await restored.authorizationServer.get("resource"), undefined)
})
