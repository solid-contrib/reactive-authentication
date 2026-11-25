import type * as oauth from "oauth4webapi"
import type {SubjectToken} from "../SubjectTokenProvider.js"
import type {TokenExchangeDPoPAdapter} from "../TokenExchangeTokenProvider.js"

type ProofHandle = oauth.DPoPHandle & {
    addProof(url: URL, headers: Headers, htm: string, accessToken?: string): Promise<void>
}

/**
 * Adds an `ath` claim over the subject token to the DPoP proof of the token exchange request, which Inrupt ESS requires when the subject token is DPoP-bound. No specification defines it: {@link https://www.rfc-editor.org/rfc/rfc9449.html#section-4.2 RFC 9449 § 4.2} defines `ath` only for access tokens at protected resources.
 *
 * It changes an internal method of the oauth4webapi DPoP handle, so that the nonce handling of oauth4webapi stays.
 *
 * @see {@link https://solidproject.org/TR/oidc#dpop-validation Solid-OIDC § 9.3 DPoP Validation}, which requires a DPoP proof when a DPoP-bound ID token is used.
 */
export const essDPoPAdapter: TokenExchangeDPoPAdapter = (handle: oauth.DPoPHandle, subjectToken: SubjectToken) => {
    const proofHandle = handle as ProofHandle
    const addProof = proofHandle.addProof

    proofHandle.addProof = (url, headers, htm) => addProof.call(proofHandle, url, headers, htm, subjectToken.token)

    return proofHandle
}
