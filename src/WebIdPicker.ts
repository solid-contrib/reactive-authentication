import { Mutex } from "./Mutex.js"
import { WebIdRequestCancelledError } from "./WebIdRequestCancelledError.js"

const onlyOnce = {once: true}
const searchString = "YOUR_USERNAME"
const html = `
<dialog>
    <fieldset>
        <legend>
            <slot name="legend">WebID required</slot>
        </legend>
        <p>
            <span>
                <slot name="description">The application needs a WebID so it can derive an Authorization Server URI from the profile to handle the following request URI.</slot>
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
                    <slot name="label">WebID</slot>
                </span>
                <input autofocus required type="url" list="autocomplete">
                <datalist id="autocomplete"></datalist>
            </label>
            <button>
                <slot name="ok-button">OK</slot>
            </button>
            <button type="button" id="cancel">
                <slot name="cancel-button">Cancel</slot>
            </button>
        </form>
    </fieldset>
</dialog>
`

export class WebIdPicker extends HTMLElement {
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

        shadow.querySelector("form")!.addEventListener("submit", () => this.#dialog.returnValue = this.#input.value)
        shadow.querySelector("#cancel")!.addEventListener("click", () => this.#dialog.close())
        this.#input.addEventListener("change", () => {
            if (this.#input.value.includes(searchString)) {
                const start = this.#input.value.indexOf(searchString)
                this.#input.setSelectionRange(start, start + searchString.length, "forward")
            }
        })

        for (const option of this.querySelectorAll(":scope > option")) {
            shadow.querySelector("datalist")!.appendChild(option.cloneNode())
        }
    }

    async getWebId(request: Request): Promise<URL> {
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
                reject(new WebIdRequestCancelledError(request))
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
