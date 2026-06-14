import { ReactiveAuthenticationError } from "./ReactiveAuthenticationError.js"

export class WebIdRequestCancelledError extends ReactiveAuthenticationError {
    constructor(public request: Request, cause?: any) {
        super("WebID request cancelled", cause)
        this.name = "WebIdRequestCancelledError"
    }
}
