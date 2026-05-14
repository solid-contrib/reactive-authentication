export class ReactiveFetchWorkerManager {
    #getCode

    constructor(getCodeCallback) {
        this.#getCode = getCodeCallback
    }

    async register() {
        navigator.serviceWorker.addEventListener("message", this.#onMessage.bind(this))

        await navigator.serviceWorker.register("./reactive-fetch-worker.js", {type: "module"})
        await navigator.serviceWorker.ready
    }

    async #onMessage(e) {
        e.ports[0].postMessage(await this.#getCode(e.data))
    }
}
