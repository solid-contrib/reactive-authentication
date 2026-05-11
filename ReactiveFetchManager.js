export class ReactiveFetchManager extends EventTarget {
    #globalFetch
    #providers

    constructor(providers) {
        super()

        this.#providers = providers

        this.#globalFetch = globalThis.fetch
        globalThis.fetch = this.#fetch.bind(this)
    }

    async #fetch(input, init) {
        const request = new Request(input, init)
        const response = await this.#globalFetch.call(undefined, request.clone())
        if (response.status !== 401) {
            return response
        }

        const provider = await this.#findProvider(request)
        if (provider === undefined) {
            return response
        }

        const upgraded = await provider.upgrade(request)
        return this.#globalFetch.call(undefined, upgraded)
    }

    async #findProvider(request) {
        for (const provider of this.#providers) {
            if (await provider.matches(request)) {
                return provider
            }
        }
    }
}
