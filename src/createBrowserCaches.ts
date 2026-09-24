import type * as oauth from "oauth4webapi"
import type { Cache } from "./Cache.js"
import type { DPoPTokenCacheEntry } from "./DPoPTokenProvider.js"
import { ExpiringCache } from "./ExpiringCache.js"
import { IndexedDbCache } from "./IndexedDbCache.js"
import { MemoryCache } from "./MemoryCache.js"

export interface ProviderCaches {
    issuer: Cache<string>
    authorizationServer: Cache<oauth.AuthorizationServer>
    client: Cache<oauth.Client>
    token: Cache<DPoPTokenCacheEntry>
}

/**
 * Explicit browser preset: public metadata in IndexedDB for one hour by default;
 * client registrations and credentials in memory. Namespace must isolate app/account
 * contexts. IndexedDB failures reject; unavailable IndexedDB is not silently ignored.
 */
export function createBrowserCaches(namespace: string, metadataMaxAgeMs = 60 * 60 * 1000): ProviderCaches {
    if (namespace.length === 0) throw new TypeError("A cache namespace is required")
    return {
        issuer: new ExpiringCache(new IndexedDbCache(`${namespace}:v1:issuer`), metadataMaxAgeMs),
        authorizationServer: new ExpiringCache(new IndexedDbCache(`${namespace}:v1:authorization-server`), metadataMaxAgeMs),
        client: new MemoryCache(),
        token: new MemoryCache(),
    }
}
