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

/**
 * A web component (custom HTML element) that manages the user experience for OAuth 2.0 Authorization Code Grant.
 *
 * Put on an HTML page and connect to a token provider to implement the Authorization Code Flow using a popup.
 *
 * @remarks
 * This element is not {@link customElements.define defined} when importing the module. Import {@link registerElements} to define it.
 *
 * See the {@link getCode} method for integrating this element into your application.
 *
 * The appearance of this web component can be customized from the hosting HTML by using {@link https://developer.mozilla.org/en-US/docs/Web/CSS/Reference/Selectors/::part CSS parts}.
 * The following parts are available:
 * - `new dialog`: A {@link https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/dialog `dialog`} shown when the user needs to interact with the authorization server.
 * - `new text`: A {@link https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/p `p`} that describes the dialog.
 * - `new open`: A {@link https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/button `button`} that opens the authorization request popup.
 * - `new cancel`: A {@link https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/button `button`} that cancels the authorization request and closes the popup.
 * - `switch dialog`: A {@link https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/dialog `dialog`} shown when there is an authorization request popup open.
 * - `switch text`: A {@link https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/p `p`} that describes the dialog.
 * - `switch open`: A {@link https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/button `button`} that switches to the authorization request popup.
 * - `switch cancel`: A {@link https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/button `button`} that cancels the authorization request and closes the popup.
 *
 * The text of this web component can be customized from the hosting HTML by using {@link https://developer.mozilla.org/en-US/docs/Web/API/Web_components/Using_templates_and_slots slots}.
 * The following named slots are available:
 * - `new-text`: Child of the `new text` paragraph.
 * - `new-open`: Child of the `new open` button.
 * - `new-cancel`: Child of the `new cancel` button.
 * - `switch-text`: Child of the `switch text` paragraph.
 * - `switch-open`: Child of the `switch open` button.
 * - `switch-cancel`: Child of the `switch cancel` button.
 *
 * @example Minimal usage
 * ```html
 * <script src="https://unpkg.com/@solid/reactive-authentication/dist/registerElements.js"></script>
 * <authorization-code-flow></authorization-code-flow>
 * ```
 *
 * @example Customizing text using slots
 * Any of the named slots can be used to customize the text shown in the dialogs:
 * ```html
 * <authorization-code-flow>
 *   <span slot="new-text">text of first (new) dialog</span>
 *   <span slot="new-open">text of first (new) dialog open button</span>
 *   <span slot="new-cancel">text of first (new) dialog cancel button</span>
 *   <span slot="switch-text">text of second (switch) dialog</span>
 *   <span slot="switch-open">text of second (switch) dialog open button</span>
 *   <span slot="switch-cancel">text of second (switch) dialog cancel button</span>
 * </authorization-code-flow>
 * ```
 *
 * @example Customizing appearance using CSS parts
 * CSS on the page hosting this web component can be used to customize the appearance of the elements that constitute its user interface:
 * ```html
 * <authorization-code-flow></authorization-code-flow>
 * <style>
 *   authorization-code-flow::part(new dialog) {
 *     border: 1px solid red;
 *   }
 *
 *   authorization-code-flow::part(new text) {
 *     border: 1px solid green;
 *   }
 *
 *   authorization-code-flow::part(new open) {
 *     border: 1px solid blue;
 *   }
 *
 *   authorization-code-flow::part(new cancel) {
 *     border: 1px solid yellow;
 *   }
 *
 *   authorization-code-flow::part(switch dialog) {
 *     border: 1px dotted red;
 *   }
 *
 *   authorization-code-flow::part(switch text) {
 *     border: 1px dotted green;
 *   }
 *
 *   authorization-code-flow::part(switch open) {
 *     border: 1px dotted blue;
 *   }
 *
 *   authorization-code-flow::part(switch cancel) {
 *     border: 1px dotted yellow;
 *   }
 * </style>
 * ```
 */
export class AuthorizationCodeFlow extends HTMLElement {
    readonly #mutex = new Mutex
    #newModal!: HTMLDialogElement
    #switchModal!: HTMLDialogElement
    #authorizationWindow?: WindowProxy | null
    #authorizationUri?: URL
    #cancelCodeRequest?: (reason?: any) => void

    /** @ignore */
    connectedCallback() {
        const template = this.ownerDocument.createElement("template")
        template.innerHTML = html

        const shadow = this.attachShadow({mode: "closed"})
        shadow.appendChild(this.ownerDocument.importNode(template.content, true))

        this.#newModal = shadow.querySelector("dialog[part *= 'new']")!
        this.#switchModal = shadow.querySelector("dialog[part *= 'switch']")!

        shadow.querySelector("form")!.addEventListener("submit", this.#onSubmit.bind(this))
    }

    /**
     * a {@link GetCodeCallback} that provides an authorization code by directing the user to the {@link authorizationUri authorization endpoint URI} in a popup and waiting for the code in a redirect back.
     *
     * @remarks Only one flow runs at a time. Any number of calls
     *
     * @param {URL} authorizationUri - The endpoint that the user should be directed to for authorization.
     * @param {AbortSignal} signal - An abort signal that can be used to cancel the authorization flow.
     *
     * @return {Promise<string>} A promise that resolves with the authorization code received from the popup window.
     *
     * @example Using manually
     * ```html
     * <authorization-code-flow></authorization-code-flow>
     * <script>
     *   const authorizationUri = new URL("http://example.com/authorize")
     *   const ui = document.querySelector("authorization-code-flow")
     *   const signal = new AbortController().signal
     *
     *   const code = await ui.getCode(authorizationUri, signal)
     * </script>
     * ```
     *
     * @example Using with a token provider
     * ```html
     * <authorization-code-flow></authorization-code-flow>
     * <script>
     *   const callbackUri = "http://localhost:8080/callback.html"
     *   const ui = document.querySelector("authorization-code-flow")
     *
     *   const provider = new DPoPTokenProvider(callbackUri, ui.getCode.bind(ui))
     *   new ReactiveFetchManager([provider])
     * </script>
     * ```
     */
    async getCode(authorizationUri: URL, signal: AbortSignal): Promise<string> {
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
