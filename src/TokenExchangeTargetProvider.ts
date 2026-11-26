/**
 * What a token exchange asks for: the authorization server that performs it and the resource that the access token is for.
 */
export interface TokenExchangeTarget {
    /**
     * The issuer identifier of the authorization server ({@link https://www.rfc-editor.org/rfc/rfc8414#section-2 RFC 8414 § 2}), which has the token endpoint.
     */
    issuer: string

    /**
     * The `resource` parameter of the token exchange request ({@link https://www.rfc-editor.org/rfc/rfc8693#section-2.1 RFC 8693 § 2.1}): the URI of the resource that the access token is for.
     */
    resource: string
}

/**
 * Finds the {@link TokenExchangeTarget} of a request that got a 401 response.
 *
 * @see {@link https://w3c.github.io/lws-protocol/lws10-oauth/#authorization-server-discovery LWS10-OAUTH Authorization Server Discovery}, for an example of how a target can be discovered.
 */
export interface TokenExchangeTargetProvider {
    /**
     * Tells if this provider can find a target for the response. It must be cheap and make no network request.
     */
    matches(request: Request, response: Response): boolean | Promise<boolean>

    /**
     * Finds the target. It can make network requests.
     *
     * @throws If it cannot find a target.
     */
    getTarget(request: Request, response: Response, signal: AbortSignal): Promise<TokenExchangeTarget>
}
