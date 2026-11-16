import type { CacheKeyProvider } from "./CacheKeyProvider.js"
import { UnrecognizedRequestUri } from "./UnrecognizedRequestUri.js"

export class PatternCacheKeyProvider implements CacheKeyProvider {
    private readonly patterns: URLPattern[]

    constructor(...patterns: URLPattern[]) {
        for (const pattern of patterns) {
            if (pattern.pathname !== "*" && !pattern.pathname.endsWith("/*")) {
                // TODO: Throw a specific error type, like elsewhere in the codebase
                throw new TypeError(`Pattern pathname must end in "/*": ${pattern.pathname}`)
            }
        }

        this.patterns = patterns
    }

    async getKey(request: Request): Promise<string> {
        for (const pattern of this.patterns) {
            const result = pattern.exec(request.url)

            if (result === null) {
                continue
            }

            return PatternCacheKeyProvider.toKey(request, result)
        }

        throw new UnrecognizedRequestUri(request)
    }

    private static toKey(request: Request, result: URLPatternResult): string {
        // Path of request URI
        const path = result.pathname.input

        // Keys of unnamed groups are numbers, listed first and in ascending order regardless of named groups
        const indices = Object.keys(result.pathname.groups).filter(key => /^\d+$/.test(key))

        // Constructor ensures pattern ends in unnamed "*", so last unnamed group is text after container
        const rest = result.pathname.groups[indices.at(-1)!] ?? ""

        // Container path ends in / because pattern ends in /*. Empty when pattern is *
        const container = path.slice(0, path.length - rest.length)

        // Empty container means root. Resolving against request URI adds origin
        return new URL(container || "/", request.url).href
    }
}
