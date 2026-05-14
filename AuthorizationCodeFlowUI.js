import { Mutex } from "./Mutex.js"

const authorizationWindowName = "oidcAuthentication"

export class AuthorizationCodeFlowUI {
    #newModal
    #switchModal
    #authorizationWindow
    #mutex = new Mutex
    #authorizationUri

    constructor() {
        this.#newModal = document.body.appendChild(document.createElement("dialog"))
        this.#newModal.innerHTML = `User interaction needed to launch authorization code flow in new window. <button>Open new window</button>` // TODO: configurable text
        this.#newModal.closedBy = "none"
        this.#newModal.querySelector("button").addEventListener("click", this.#openAuthorizationWindow.bind(this))

        this.#switchModal = document.body.appendChild(document.createElement("dialog"))
        this.#switchModal.innerHTML = `There is an ongoing authorization code flow in another window. <button>Switch to ongoing flow</button>` // TODO: configurable text
        this.#switchModal.closedBy = "none"
        this.#switchModal.querySelector("button").addEventListener("click", () => this.#authorizationWindow.focus())
    }

    async onCodeRequired(codeRequest) {
        // One flow at a time, fellas
        using _ = await this.#mutex.acquire()

        // TODO: Formalize code request event shape
        this.#authorizationUri = codeRequest.detail

        const authorizationCodeResponse = await new Promise(resolve => {
            window.addEventListener("message", message => {
                this.#switchModal.close()
                message.source.close()
                resolve(message.data)
            }, {once: true})

            this.#openAuthorizationWindow()

            if (this.#authorizationWindow == null) {
                this.#interactionNeeded()
            }
        })

        codeRequest.resolve(authorizationCodeResponse)
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
