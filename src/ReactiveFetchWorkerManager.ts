import type { CodeProvider } from "./CodeProvider.js"

export class ReactiveFetchWorkerManager {
    readonly #codeProvider: CodeProvider

    constructor(codeProvider: CodeProvider) {
        this.#codeProvider = codeProvider
    }

    async register() {
        navigator.serviceWorker.addEventListener("message", this.#onMessage.bind(this))

        await navigator.serviceWorker.register("./dist/reactive-fetch-worker.ts", {type: "module"})
        await navigator.serviceWorker.ready
    }

    async #onMessage(e: MessageEvent<string>) {
        e.ports[0]?.postMessage(await this.#codeProvider.getCode(new URL(e.data), null!)) // TODO: Signal?
    }
}
