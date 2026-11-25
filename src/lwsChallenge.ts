import type {WWWAuthenticateChallenge} from "oauth4webapi"

/**
 * The parameters of a storage server challenge as defined in {@link https://www.w3.org/TR/2026/WD-lws10-core-20260331/#x5-2-1-authorization-server-discovery LWS 1.0 Core § 5.2.1 Authorization Server Discovery}.
 */
export interface LwsChallenge {
    /**
     * The issuer of the authorization server that issues access tokens for the storage.
     */
    asUri: string

    /**
     * The protection space of the storage. It is the `resource` of the {@link https://www.w3.org/TR/2026/WD-lws10-core-20260331/#x5-2-3-1-request token exchange request}.
     */
    realm: string
}

/**
 * Finds the first `Bearer` or `DPoP` challenge that has absolute `as_uri` and `realm` URIs as defined in {@link https://www.w3.org/TR/2026/WD-lws10-core-20260331/#x5-2-1-authorization-server-discovery LWS 1.0 Core § 5.2.1 Authorization Server Discovery}.
 *
 * The `realm` parameter is from {@link https://www.rfc-editor.org/rfc/rfc6750#section-3 RFC 6750 § 3}. The `as_uri` parameter is from {@link https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-grant-2.0.html#rfc.section.3.2.1 UMA 2.0 Grant § 3.2.1}, which uses it with the `UMA` scheme.
 */
export function findLwsChallenge(challenges: readonly WWWAuthenticateChallenge[]): LwsChallenge | undefined {
    for (const challenge of challenges) {
        if (challenge.scheme !== "bearer" && challenge.scheme !== "dpop") {
            continue
        }

        const asUriValue = challenge.parameters.as_uri
        const realmValue = challenge.parameters.realm

        if (asUriValue === undefined || realmValue === undefined) {
            continue
        }

        if (URL.canParse(asUriValue) && URL.canParse(realmValue)) {
            return {asUri: asUriValue, realm: realmValue}
        }
    }

    return undefined
}

/**
 * Checks that a request URI is logically contained in a realm, as required by {@link https://www.w3.org/TR/2026/WD-lws10-core-20260331/#x5-2-1-authorization-server-discovery LWS 1.0 Core § 5.2.1 Authorization Server Discovery}.
 *
 * The request URI must have the same origin as the realm, and its path must be the realm path or below it on a segment boundary.
 */
export function isWithinRealm(requestUrl: URL, realmUri: string): boolean {
    const realm = new URL(realmUri)

    if (requestUrl.origin !== realm.origin) {
        return false
    }

    const base = realm.pathname.endsWith("/") ? realm.pathname.slice(0, -1) : realm.pathname

    return requestUrl.pathname === base || requestUrl.pathname.startsWith(base + "/")
}
