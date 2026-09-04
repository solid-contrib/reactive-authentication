import { IssuerProvider } from "./IssuerProvider.js"

export class CachingIssuerProvider implements IssuerProvider {
    readonly #cache = new Map<string, URL> // TODO: Take cache from caller
    readonly #original: IssuerProvider

    constructor(original: IssuerProvider) {
        this.#original = original
    }

    async getIssuer(request: Request): Promise<URL> {
        const cached = this.#cache.get(request.url)
        if (cached !== undefined) {
            return cached
        }

        const fresh = await this.#original.getIssuer(request)
        this.#cache.set(request.url, fresh)
        return fresh
    }
}
