import { Mutex } from "./Mutex.js"
import { CodeRequestCancelledError } from "./CodeRequestCancelledError.js"

const authorizationWindowName = "oidcAuthentication"
const onlyOnce = {once: true}
const html = `
<style>
</style>
<form>
    <dialog part="new dialog" closedby="none">
        <p part="new text">
            <slot name="new-text">User interaction needed to launch authorization code flow in new window.</slot>
        </p>
        <button part="new open button" value="open">
            <slot name="new-open">Open new window</slot>
        </button>
        <button part="new cancel button" value="cancel">
            <slot name="new-cancel">Cancel</slot>
        </button>
    </dialog>
    <dialog part="switch dialog" closedby="none">
        <p part="switch text"> 
            <slot name="switch-text">There is an ongoing authorization code flow in another window.</slot>
        </p>
        <button part="switch open button" value="focus">
            <slot name="switch-open">Switch to ongoing flow</slot>
        </button>
        <button part="switch cancel button" value="cancel">
            <slot name="switch-cancel">Cancel</slot>
        </button>
    </dialog>
</form>
`

class AuthorizationCodeFlowUI extends HTMLElement {
    readonly #mutex = new Mutex
    #newModal!: HTMLDialogElement
    #switchModal!: HTMLDialogElement
    #authorizationWindow?: WindowProxy | null
    #authorizationUri?: URL
    #cancelCodeRequest?: (reason?: any) => void

    connectedCallback() {
        const template = this.ownerDocument.createElement("template")
        template.innerHTML = html

        const shadow = this.attachShadow({mode: "closed"})
        shadow.appendChild(this.ownerDocument.importNode(template.content, true))

        this.#newModal = shadow.querySelector(`dialog[part *= "new"]`)!
        this.#switchModal = shadow.querySelector(`dialog[part *= "switch"]`)!

        shadow.querySelector("form")!.addEventListener("submit", this.#onSubmit.bind(this))
    }

    async onCodeRequired(authorizationUri: URL, signal: AbortSignal): Promise<string> {
        // One flow at a time, fellas
        using _ = await this.#mutex.acquire()

        this.#authorizationUri = authorizationUri

        const {promise: responseFromPopup, reject: cancelCodeRequest, resolve: respondWithCode} = Promise.withResolvers<string>()
        signal.throwIfAborted()

        this.#cancelCodeRequest = cancelCodeRequest

        const onMessage = (message: MessageEvent) => {
            signal.removeEventListener("abort", onAbort)
            this.#switchModal.close()
            this.#authorizationWindow?.close()
            respondWithCode(message.data)
        }

        const onAbort = () => {
            this.ownerDocument.defaultView?.removeEventListener("message", onMessage)
            this.#newModal.close()
            this.#switchModal.close()
            this.#authorizationWindow?.close()
            cancelCodeRequest(signal.reason)
        }

        signal.addEventListener("abort", onAbort, onlyOnce)
        this.ownerDocument.defaultView?.addEventListener("message", onMessage, onlyOnce)

        this.#openAuthorizationWindow()

        if (this.#authorizationWindow === null) {
            this.#interactionNeeded()
        }

        return await responseFromPopup
    }

    #onSubmit(e: SubmitEvent) {
        e.preventDefault()

        switch ((e.submitter as HTMLButtonElement).value) {
            case "open":
                this.#openAuthorizationWindow()
                break
            case "focus":
                this.#authorizationWindow?.focus()
                break
            case "cancel":
                this.#cancel()
                break
        }
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

customElements.define("authorization-code-flow-ui", AuthorizationCodeFlowUI)
