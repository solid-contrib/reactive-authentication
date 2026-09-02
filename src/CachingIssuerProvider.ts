import { IssuerProvider } from "./IssuerProvider.js"

export class CachingIssuerProvider implements IssuerProvider {
    readonly #cache = new Map<string, Promise<URL>> // TODO: Take cache from caller
    readonly #original: IssuerProvider

    constructor(original: IssuerProvider) {
        this.#original = original
    }

    getIssuer(request: Request): Promise<URL> {
        return this.#cache.getOrInsertComputed(request.url, _ => this.#original.getIssuer(request))
    }
}
