import type { CacheKeyProvider } from "./CacheKeyProvider.js"

export class UrlCacheKeyProvider implements CacheKeyProvider {
    async getKey(request: Request): Promise<string> {
        return request.url
    }
}
