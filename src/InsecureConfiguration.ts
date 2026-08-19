import * as oauth from "oauth4webapi"

/**
 * Global opt-in switch for oauth4webapi's HTTPS enforcement.
 *
 * @remarks
 * Enforcement is on by default. Consumers targeting a plain HTTP issuer, such as a
 * Community Solid Server on `http://localhost:3000`, opt out for themselves.
 */
export class InsecureConfiguration {
    static #allowed = false

    /**
     * Allows OAuth requests over plain HTTP.
     *
     * @remarks
     * Deprecated on purpose, so that consumers see the security implication at the call site.
     *
     * @deprecated Only ever call this in local development.
     */
    static allow() {
        console.error("Insecure requests allowed for oauth4webapi")
        this.#allowed = true
    }

    static get requestOptions(): {[oauth.allowInsecureRequests]?: boolean} {
        return {[oauth.allowInsecureRequests]: this.#allowed}
    }
}
