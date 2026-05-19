import { Mutex } from "./Mutex.js"
import { CodeRequestCancelledError } from "./CodeRequestCancelledError.js"

const authorizationWindowName = "oidcAuthentication"

export class AuthorizationCodeFlowUI {
    readonly #mutex = new Mutex
    readonly #newModal: HTMLDialogElement
    readonly #switchModal: HTMLDialogElement
    #authorizationWindow?: WindowProxy | null
    #authorizationUri?: URL
    #cancelCodeRequest?: (reason?: any) => void

    constructor() {
        this.#newModal = document.body.appendChild(document.createElement("dialog"))
        this.#newModal.innerHTML = `User interaction needed to launch authorization code flow in new window. <button>Open new window</button> <button>Cancel</button>` // TODO: configurable text
        this.#newModal.closedBy = "none"
        this.#newModal.querySelector("button:first-child")!.addEventListener("click", this.#openAuthorizationWindow.bind(this))
        this.#newModal.querySelector("button:last-child")!.addEventListener("click", this.#cancel.bind(this))

        this.#switchModal = document.body.appendChild(document.createElement("dialog"))
        this.#switchModal.innerHTML = `There is an ongoing authorization code flow in another window. <button>Switch to ongoing flow</button> <button>Cancel</button>` // TODO: configurable text
        this.#switchModal.closedBy = "none"
        this.#switchModal.querySelector("button:first-child")!.addEventListener("click", () => this.#authorizationWindow?.focus())
        this.#switchModal.querySelector("button:last-child")!.addEventListener("click", this.#cancel.bind(this))
    }

    async onCodeRequired(authorizationUri: URL): Promise<string> {
        // One flow at a time, fellas
        using _ = await this.#mutex.acquire()

        this.#authorizationUri = authorizationUri

        return await new Promise((resolve, reject) => {
            this.#cancelCodeRequest = reject

            window.addEventListener("message", message => {
                this.#switchModal.close()
                this.#authorizationWindow?.close()
                resolve(message.data)
            }, {once: true})

            this.#openAuthorizationWindow()

            if (this.#authorizationWindow === null) {
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

    #cancel() {
        this.#newModal.close()
        this.#switchModal.close()
        this.#authorizationWindow?.close()
        this.#cancelCodeRequest?.call(undefined, new CodeRequestCancelledError(this.#authorizationUri!))
    }
}
