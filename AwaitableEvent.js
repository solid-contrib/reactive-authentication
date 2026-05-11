export class AwaitableEvent extends CustomEvent {
    #resolve

    constructor(type, resolve, eventInitDict) {
        super(type, eventInitDict)

        this.#resolve = resolve
    }

    get resolve() {
        return this.#resolve
    }
}
