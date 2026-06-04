export class ReactiveAuthenticationError extends Error {
    constructor(message?: string, cause?: any) {
        super(message)
        this.name = "ReactiveFetchError"
        this.cause = cause
    }
}
