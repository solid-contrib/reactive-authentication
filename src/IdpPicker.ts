import { Mutex } from "./Mutex.js"
import { IssuerRequestCancelledError } from "./IssuerRequestCancelledError.js"

const onlyOnce = {once: true}
const html = `
<dialog>
    <fieldset>
        <legend>
            <slot name="legend">Authorization Server URI required</slot>
        </legend>
        <p>
            <span>
                <slot name="description">The application needs an Authorization Server URI so it can handle the following request URI.</slot>
            </span>
            <details>
                <summary>
                    <slot name="summary">Request URI</slot>
                </summary>
                <code></code>
            </details>
        </p>
        <form method="dialog">
            <label>
                <span>
                    <slot name="inputlabel">Authorization Server URI</slot>
                </span>
                <input autofocus required type="url" list="autocomplete">
                <datalist id="autocomplete"></datalist>
            </label>
            <button>
                <slot name="ok-button">OK</slot>
            </button>
            <button type="button">
                <slot name="cancel-button">Cancel</slot>
            </button>
        </form>
    </fieldset>
</dialog>
`

/**
 * A web component (custom HTML element) that prompts the user for the URI of the authorization server (identity provider) to use for a request.
 *
 * @remarks
 * This element is not {@link customElements.define defined} when importing the module. Import {@link registerElements} to define it.
 *
 * See the {@link getIssuer} method for integrating this element into your application.
 */
export class IdpPicker extends HTMLElement {
    readonly #mutex = new Mutex
    #dialog!: HTMLDialogElement
    #input!: HTMLInputElement
    #code!: HTMLElement

    /** @ignore */
    connectedCallback() {
        const template = this.ownerDocument.createElement("template")
        template.innerHTML = html

        const shadow = this.attachShadow({mode: "closed"})
        shadow.appendChild(this.ownerDocument.importNode(template.content, true))

        this.#dialog = shadow.querySelector("dialog")!
        this.#input = shadow.querySelector("input")!
        this.#code = shadow.querySelector("code")!

        shadow.querySelector("form")!.addEventListener("submit", e => this.#dialog.returnValue = this.#input.value)
        shadow.querySelector("button[type = 'button']")!.addEventListener("click", () => this.#dialog.close())

        for (const option of this.querySelectorAll("option")) {
            shadow.querySelector("datalist")!.appendChild(option.cloneNode())
        }
    }

    async getIssuer(request: Request): Promise<URL> {
        using _ = await this.#mutex.acquire()

        this.#input.value = ""
        this.#code.innerText = request.url
        this.#dialog.returnValue = ""
        this.#dialog.showModal()

        const {promise, reject, resolve} = Promise.withResolvers<URL>()

        const onClose = () => {
            request.signal.removeEventListener("abort", onAbort)
            if (this.#dialog.returnValue !== "") {
                resolve(new URL(this.#dialog.returnValue))
            } else {
                reject(new IssuerRequestCancelledError(request))
            }
        }
        const onAbort = () => {
            this.#dialog.removeEventListener("close", onClose)
            this.#dialog.close()
            reject(request.signal.reason)
        }

        request.signal.addEventListener("abort", onAbort, onlyOnce)
        this.#dialog.addEventListener("close", onClose, onlyOnce)

        return await promise
    }
}
