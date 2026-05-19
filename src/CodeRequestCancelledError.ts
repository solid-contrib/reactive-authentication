import { ReactiveFetchError } from "./ReactiveFetchError.js"

export class CodeRequestCancelledError extends ReactiveFetchError {
    constructor(public authorizationRequest: URL, cause?: any) {
        super("Code request cancelled", cause)
        this.name = "CodeRequestCancelledError"
    }
}
