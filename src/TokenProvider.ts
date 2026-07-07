export interface TokenProvider {
    matches(request: Request): Promise<boolean>

    upgrade(request: Request): Promise<Request>

    /**
     * Optional: called when a request this provider upgraded was still rejected
     * with 401 — the attached credentials were revoked, invalidated early, or
     * expired without a server-reported lifetime. The provider should mark any
     * cached credentials for the request stale so the next {@link upgrade}
     * renews them instead of replaying the rejected ones.
     *
     * @param request - The rejected upgraded request (carrying the credentials this provider attached).
     */
    invalidate?(request: Request): Promise<void>

    /**
     * Optional: definitively drops any cached session for the request's target
     * — the "log out" / "switch account" primitive. In contrast to
     * {@link invalidate} (transient — keeps the durable credential so the
     * session silently re-establishes), a provider implementing `forget` should
     * discard the whole session, including any refresh token, so it does NOT
     * come back until the next interactive authorization. Implementations should
     * make this safe against a concurrent {@link upgrade} completing with the
     * discarded credentials.
     *
     * @param request - A request identifying the session (target/issuer) to forget.
     */
    forget?(request: Request): Promise<void>
}
