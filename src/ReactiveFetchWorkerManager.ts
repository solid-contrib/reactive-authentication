import type { GetCodeCallback } from "./GetCodeCallback.js"

export class ReactiveFetchWorkerManager {
    readonly #getCode: GetCodeCallback

    constructor(getCodeCallback: GetCodeCallback) {
        this.#getCode = getCodeCallback
    }

    async register() {
        navigator.serviceWorker.addEventListener("message", this.#onMessage.bind(this))

        await navigator.serviceWorker.register("./dist/reactive-fetch-worker.ts", {type: "module"})
        await navigator.serviceWorker.ready
    }

    async #onMessage(e: MessageEvent<string>) {
        e.ports[0]?.postMessage(await this.#getCode(new URL(e.data), null!)) // TODO: Signal?
    }
}
