import * as oauth from "oauth4webapi"
import {ReactiveAuthenticationError} from "./ReactiveAuthenticationError.js"

const preference = ["ES256", "EdDSA", "PS256", "RS256"]

/**
 * Selects the algorithm of the DPoP key pair from the algorithms that an authorization server supports.
 *
 * The first algorithm of ES256, EdDSA, PS256 and RS256 that the server lists wins.
 * The order puts the most widely supported algorithm first, then the compact ones, and prefers RSASSA-PSS over RSASSA-PKCS1-v1_5.
 * All four are accepted by oauth4webapi's `generateKeyPair`.
 *
 * @remarks
 * Falls back to ES256 when the server does not advertise `dpop_signing_alg_values_supported`.
 * An advertised empty list counts as a list without a match.
 * Pass the result to `oauth.generateKeyPair` with `extractable: false`.
 *
 * @param as The authorization server metadata.
 * @returns A JOSE algorithm name.
 * @throws {ReactiveAuthenticationError} When the server advertises algorithms and none of them is supported here.
 *
 * @see Spec https://www.rfc-editor.org/rfc/rfc9449.html#section-5.1
 * @see {@link oauth.generateKeyPair}
 */
export function selectDPoPSigningAlgorithm(as: oauth.AuthorizationServer) {
    const supported = as.dpop_signing_alg_values_supported

    if (supported === undefined) {
        return "ES256"
    }

    const algorithm = preference.find(candidate => supported.includes(candidate))

    if (algorithm === undefined) {
        throw new ReactiveAuthenticationError(`The authorization server supports none of the DPoP signing algorithms [${preference.join(", ")}]. It advertises [${supported.join(", ")}].`)
    }

    return algorithm
}
