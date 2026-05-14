import { Mutex } from "./Mutex.js"

const authorizationWindowName = "oidcAuthentication"

export class AuthorizationCodeFlowUI {
    readonly #mutex = new Mutex
    readonly #newModal: HTMLDialogElement
    readonly #switchModal: HTMLDialogElement
    #authorizationWindow?: WindowProxy | null
    #authorizationUri?: URL

    constructor() {
        this.#newModal = document.body.appendChild(document.createElement("dialog"))
        this.#newModal.innerHTML = `User interaction needed to launch authorization code flow in new window. <button>Open new window</button>` // TODO: configurable text
        ;(this.#newModal as any).closedBy = "none"
        this.#newModal.querySelector("button")!.addEventListener("click", this.#openAuthorizationWindow.bind(this))

        this.#switchModal = document.body.appendChild(document.createElement("dialog"))
        this.#switchModal.innerHTML = `There is an ongoing authorization code flow in another window. <button>Switch to ongoing flow</button>` // TODO: configurable text
        ;(this.#switchModal as any).closedBy = "none"
        this.#switchModal.querySelector("button")!.addEventListener("click", () => this.#authorizationWindow?.focus())
    }

    async onCodeRequired(authorizationUri: URL): Promise<string> {
        // One flow at a time, fellas
        using _ = await this.#mutex.acquire()

        this.#authorizationUri = authorizationUri

        return await new Promise(resolve => {
            window.addEventListener("message", message => {
                this.#switchModal.close()
                ;(message.source as Window).close()
                resolve(message.data)
            }, {once: true})

            this.#openAuthorizationWindow()

            if (this.#authorizationWindow == null) {
                this.#interactionNeeded()
            }
        })
    }

    #interactionNeeded() {
        this.#switchModal.close()
        this.#newModal.showModal()
    }

    #openAuthorizationWindow() {
        this.#authorizationWindow = open(this.#authorizationUri, authorizationWindowName)
        this.#newModal.close()
        this.#switchModal.showModal()
    }
}
