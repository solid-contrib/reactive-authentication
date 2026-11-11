export interface CacheKeyProvider {
    getKey(request: Request): Promise<string>
}
