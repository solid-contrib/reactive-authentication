import { ReactiveAuthenticationError } from "./ReactiveAuthenticationError.js"

/**
 * Thrown by {@link DPoPTokenProvider.upgrade} when the session it was
 * establishing/reusing was {@link DPoPTokenProvider.forget | forgotten} while
 * the upgrade was in flight.
 *
 * @remarks
 * This is the fail-closed outcome of the supersession fence: once a session is
 * forgotten (e.g. the user logged out), a request that was already mid-upgrade
 * must NOT complete carrying that session's credentials. The reactive `fetch`
 * rejects with this error rather than silently attaching a token the consumer
 * asked to discard.
 */
export class SessionForgottenError extends ReactiveAuthenticationError {
    constructor(public issuer: URL, cause?: any) {
        super(`Session for issuer ${issuer.href} was forgotten during the upgrade`, cause)
        this.name = "SessionForgottenError"
    }
}
