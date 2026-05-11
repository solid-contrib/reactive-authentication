export class ReactiveAuthenticationClient {
    #fetch
    #providers

    constructor(fetch, providers) {
        this.#fetch = fetch
        this.#providers = providers
    }

    async fetch(request) {
        const response = await this.#fetch.call(undefined, request.clone())
        if (response.status !== 401) {
            return response
        }

        const provider = await this.#findProvider(request)
        if (provider === undefined) {
            return response
        }

        const upgraded = await provider.upgrade(request)
        return this.#fetch.call(undefined, upgraded)
    }

    async #findProvider(request) {
        for (const provider of this.#providers) {
            if (await provider.matches(request)) {
                return provider
            }
        }
    }
}