import { ReactiveAuthenticationError } from "./ReactiveAuthenticationError.js";

export class UnrecognizedRequestUri extends ReactiveAuthenticationError {
    constructor(public request: Request, cause?: any) {
        super("Unrecognized request URI", cause)
        this.name = "UnrecognizedRequestUri"
    }
}