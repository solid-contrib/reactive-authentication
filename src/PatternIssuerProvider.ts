import { IssuerProvider } from "./IssuerProvider.js"
import { UnrecognizedRequestUri } from "./UnrecognizedRequestUri.js"

export type PatternMapping = {
    pattern: RegExp,
    result: string
}

export class PatternIssuerProvider implements IssuerProvider {
    constructor(private mapping: Iterable<PatternMapping>) {
    }

    async getIssuer(request: Request): Promise<URL> {
        for (const item of this.mapping)
            if (item.pattern.test(request.url))
                return new URL(item.result)

        throw new UnrecognizedRequestUri(request)
    }
}
