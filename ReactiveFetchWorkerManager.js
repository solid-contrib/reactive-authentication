import { AwaitableEvent } from "./AwaitableEvent.js"

export class ReactiveFetchWorkerManager extends EventTarget {
    async register() {
        navigator.serviceWorker.addEventListener("message", this.#onMessage.bind(this))

        await navigator.serviceWorker.register("./reactive-fetch-worker.js", {type: "module"})
        await navigator.serviceWorker.ready
    }

    async #onMessage(e) {
        const value = await new Promise(resolve =>
            this.dispatchEvent(
                new AwaitableEvent(
                    e.data.type,
                    resolve,
                    {
                        detail: e.data.detail
                    })))

        e.ports[0].postMessage(value)
    }
}
