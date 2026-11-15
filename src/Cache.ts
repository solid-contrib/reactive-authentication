/**
 * An asynchronous key-value store used by the caching components
 * ({@link CachingIssuerProvider}, {@link CachingAuthorizationServerProvider}, {@link CachingClientProvider} and
 * {@link DPoPTokenProvider}).
 *
 * A miss returns `null`. A backend failure must reject, never look like a miss.
 * Values are the library's own objects, so a store must keep them as they are (memory, or structured clone such as
 * IndexedDB) or translate them with a codec.
 *
 * The shape matches `KeyValueStore` from Key Value Kit (https://github.com/jeswr/KeyValueKit), so its memory, Web
 * Storage, IndexedDB, Node, Bun, Deno, VS Code and Electron stores can be passed in directly.
 */
export interface Cache<T extends NonNullable<unknown>> {
    getItem(key: string): Promise<T | null>
    setItem(key: string, value: T): Promise<void>
    removeItem(key: string): Promise<void>
}
