import LinkHeader from "http-link-header"

/**
 * Finds the first target of a link with the given relation type in the `Link` header field of a response, as defined in {@link https://www.rfc-editor.org/rfc/rfc8288#section-3 RFC 8288 § 3 Link Serialisation in HTTP Headers}. This is how a storage is bound to its metadata in {@link https://www.w3.org/TR/lws10-core/#x5-1-2-discovery-and-binding LWS 1.0 Core § 5.1.2 Discovery and Binding}.
 *
 * The target is resolved against the response URL as defined in {@link https://www.rfc-editor.org/rfc/rfc8288#section-3.1 RFC 8288 § 3.1 Target IRI}. Targets that do not resolve to an absolute URL are skipped.
 *
 * Registered relation types are compared case-insensitively. Extension relation types, which are URIs, are compared exactly, as required by {@link https://www.rfc-editor.org/rfc/rfc8288#section-3.3 RFC 8288 § 3.3 Relation Type}.
 *
 * This function never throws. A missing or malformed header field gives `undefined`.
 *
 * @returns The absolute target URL, or `undefined` if there is none.
 */
export function findLinkTarget(response: Response, rel: string): string | undefined {
    const header = response.headers.get("Link")
    if (header === null) {
        return undefined
    }

    try {
        const wanted = rel.includes(":") ? rel : rel.toLowerCase()
        for (const link of LinkHeader.parse(header).refs) {
            if (typeof link.rel !== "string") {
                continue
            }

            const actual = link.rel.includes(":") ? link.rel : link.rel.toLowerCase()
            if (actual !== wanted) {
                continue
            }

            const url = URL.parse(link.uri, response.url || undefined)
            if (url !== null) {
                return url.href
            }
        }
    } catch {
        return undefined
    }

    return undefined
}
