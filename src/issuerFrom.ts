import { GetIssuerCallback } from "./GetIssuerCallback.js"
import { UnrecognizedRequestUri } from "./UnrecognizedRequestUri.js"

export type PatternMapping = {
    pattern: RegExp,
    result: string
}

export function issuerFrom(mapping: Iterable<PatternMapping>): GetIssuerCallback {
    return async request => {
        for (const item of mapping)
            if (item.pattern.test(request.url))
                return new URL(item.result)

        throw new UnrecognizedRequestUri(request)
    }
}
