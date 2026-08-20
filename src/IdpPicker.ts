import { SimpleDataset } from "./SimpleDataset.js"
import { NamedNodeAs, OptionalFrom, TermWrapper } from "@rdfjs/wrapper"
import { DataFactory, Parser } from "n3"
import type { Quad } from "@rdfjs/types"
import { ReactiveAuthenticationError } from "./ReactiveAuthenticationError.js"
import { Mutex } from "./Mutex.js"
import { IssuerRequestCancelledError } from "./IssuerRequestCancelledError.js"
import { IssuerProvider } from "./IssuerProvider.js"
import type { WebIdPicker } from "./WebIdPicker.js"

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
            <button type="button" id="webid" hidden disabled accesskey="w">
                <slot name="webid-button">Use <u>W</u>ebID</slot>
            </button>
            <button type="button" id="cancel">
                <slot name="cancel-button">Cancel</slot>
            </button>
        </form>
        <slot name="webid-picker"></slot>
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
export class IdpPicker extends HTMLElement implements IssuerProvider {
    readonly #mutex = new Mutex
    #dialog!: HTMLDialogElement
    #input!: HTMLInputElement
    #code!: HTMLElement
    #webIdButton!: HTMLButtonElement
    #webIdPicker: WebIdPicker | null = null
    #request?: Request

    /** @ignore */
    connectedCallback() {
        const template = this.ownerDocument.createElement("template")
        template.innerHTML = html

        const shadow = this.attachShadow({mode: "closed"})
        shadow.appendChild(this.ownerDocument.importNode(template.content, true))

        this.#dialog = shadow.querySelector("dialog")!
        this.#input = shadow.querySelector("input")!
        this.#code = shadow.querySelector("code")!
        this.#webIdPicker = this.querySelector(":scope > webid-picker[slot='webid-picker']")
        this.#webIdButton = shadow.querySelector<HTMLButtonElement>("#webid")!

        shadow.querySelector("form")!.addEventListener("submit", e => this.#dialog.returnValue = this.#input.value)
        shadow.querySelector("#cancel")!.addEventListener("click", () => this.#dialog.close())
        this.#webIdButton.addEventListener("click", this.#useWebId.bind(this))

        // Options cannot be slotted into a datalist
        for (const option of this.querySelectorAll(":scope > option")) {
            shadow.querySelector("datalist")!.appendChild(option.cloneNode())
        }

        this.#webIdButton.disabled = this.#webIdButton.hidden = this.#webIdPicker === null
    }

    async getIssuer(request: Request): Promise<URL> {
        using _ = await this.#mutex.acquire()

        this.#request = request
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

    async #useWebId() {
        this.#webIdButton.disabled = true
        try {
            const webid = await this.#webIdPicker!.getWebId(this.#request!)
            const issuer = await issuerFromWebId(webid, this.#request!.signal)
            this.#input.value = issuer.href
        } finally {
            this.#webIdButton.disabled = false
            this.#input.focus()
        }
    }
}

class WebIdAgent extends TermWrapper {
    get oidcIssuer(): URL | undefined {
        return OptionalFrom.subjectPredicate(this, "http://www.w3.org/ns/solid/terms#oidcIssuer", NamedNodeAs.url)
    }
}

async function issuerFromWebId(webId: URL, signal: AbortSignal): Promise<URL> {
    const response = await fetch(webId, {headers: {accept: "text/turtle"}, signal})
    if (!response.ok) {
        throw new ReactiveAuthenticationError("WebID profile could not be retrieved")
    }

    const text = await response.text()
    const parser = new Parser({baseIRI: response.url || webId.href}) // Base is from response if redirected, from WebID otherwise
    let quads: Quad[]
    try {
        quads = parser.parse(text)
    } catch (error) {
        throw new ReactiveAuthenticationError("WebID profile could not be parsed", error)
    }

    const agent = new WebIdAgent(webId.href, new SimpleDataset(quads), DataFactory)
    const issuer = agent.oidcIssuer
    if (issuer === undefined) {
        throw new ReactiveAuthenticationError("WebID profile lacks OIDC issuer")
    }

    return issuer
}
