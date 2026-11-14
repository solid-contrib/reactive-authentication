import * as oauth from "oauth4webapi"

/**
 * Runs a token endpoint request, and runs it once more if the authorization server demands a DPoP nonce.
 *
 * The server answers `use_dpop_nonce` with a `DPoP-Nonce` header when its proofs must carry a server-provided nonce
 * ({@link https://www.rfc-editor.org/rfc/rfc9449.html#section-8 RFC 9449 §8}). The nonce is validated before the grant
 * is processed, so repeating the request does not replay an authorization code or a rotated refresh token.
 *
 * `send` must perform the request and the matching `oauth.process*Response` call. oauth4webapi throws the nonce error
 * from the process step, and it stores the nonce in the `DPoP` handle at that point.
 * `send` must pass the same `DPoP` handle on every call, so the retry carries the stored nonce.
 *
 * At most one retry happens. A second nonce error, and any other error, propagates to the caller.
 *
 * @param send Request plus response processing, using one `DPoP` handle.
 * @internal
 */
export async function withDPoPNonceRetry<T>(send: () => Promise<T>): Promise<T> {
    try {
        return await send()
    } catch (e) {
        if (!oauth.isDPoPNonceError(e)) {
            throw e
        }

        return await send()
    }
}
