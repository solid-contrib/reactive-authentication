export class Mutex {
    #tail = Promise.resolve()

    async acquire() {
        let release

        // Insert a new link in the chain
        const previous = this.#tail
        this.#tail = new Promise(resolve => release = resolve)

        // Latch on to the chain
        await previous

        // Provide a way to unhook this link
        return {[Symbol.dispose]: release}
    }
}
