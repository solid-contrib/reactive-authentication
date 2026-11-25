/**
 * A subject token and its type, as sent in a token exchange request ({@link https://www.rfc-editor.org/rfc/rfc8693#section-2.1 RFC 8693 § 2.1}).
 *
 * @see {@link https://w3c.github.io/lws-protocol/lws10-oauth/#authentication LWS10-OAUTH Authentication}, which calls it an authentication credential.
 */
export interface SubjectToken {
    /**
     * The `subject_token`, for example a compact serialized ID token.
     */
    token: string

    /**
     * The `subject_token_type`, a token type URI as defined in {@link https://www.rfc-editor.org/rfc/rfc8693#section-3 RFC 8693 § 3 Token Type Identifiers}.
     */
    type: string
}

/**
 * Obtains subject tokens for the user of a request.
 */
export interface SubjectTokenProvider {
    /**
     * Gets a subject token, reusing a cached one while it is valid.
     */
    getSubjectToken(request: Request, signal: AbortSignal): Promise<SubjectToken>

    /**
     * Discards a subject token that an authorization server rejected, so that the next call to {@link getSubjectToken} for the same request obtains a new one. A subject token that is no longer the cached one is ignored.
     */
    invalidate(request: Request, subjectToken: SubjectToken): Promise<void>
}
