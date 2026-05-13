import { Mutex } from "./Mutex.js"

const authorizationWindowName = "oidcAuthentication"

export class AuthorizationCodeFlowUI {
    #modal
    #link
    #mutex = new Mutex

    constructor() {
        this.#modal = document.body.appendChild(document.createElement("dialog"))
        this.#modal.innerHTML = `<a target="${authorizationWindowName}">x</a>`
        this.#modal.closedBy = "none"

        this.#link = this.#modal.querySelector("a")
        this.#link.addEventListener("click", this.#onLinkClick.bind(this))
    }

    async onCodeRequired(codeRequest) {
        // One flow at a time, fellas
        using _ = await this.#mutex.acquire()

        // TODO: Formalize code request event shape
        const authorizationUri = codeRequest.detail

        const authorizationCodeResponse = await new Promise(resolve => {
            window.addEventListener("message", message => {
                this.#interactionNotNeeded()
                message.source.close()
                resolve(message.data)
            }, {once: true})

            const authorizationWindow = open(authorizationUri, authorizationWindowName)

            if (authorizationWindow == null) {
                this.#interactionNeeded(authorizationUri)
            }
        })

        codeRequest.resolve(authorizationCodeResponse)
    }

    #interactionNeeded(authorizationUri) {
        this.#link.href = authorizationUri
        this.#modal.showModal()
    }

    #interactionNotNeeded() {
        this.#modal.close()
    }

    #onLinkClick() {
        // TODO: `Disable` link after clicked, re-enable elsewhere when needed
    }
}

