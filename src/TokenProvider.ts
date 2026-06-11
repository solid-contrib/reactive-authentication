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
}
