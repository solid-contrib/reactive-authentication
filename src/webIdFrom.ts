import * as oauth from "oauth4webapi"

/**
 * The WebID an issuer asserted for the user, read from the `webid` claim that
 * Solid-OIDC requires the id_token to carry.
 *
 * @param response A token endpoint response processed by oauth4webapi, such as
 * the one `DPoPTokenProvider.tokenEndpointResponse` reports.
 *
 * @returns The asserted WebID, or undefined when the response carries no
 * id_token or the id_token carries no `webid` claim.
 *
 * @see [Solid-OIDC ID Tokens](https://solidproject.org/TR/oidc#tokens-id)
 */
export function webIdFrom(response: oauth.TokenEndpointResponse): string | undefined {
    const webId = oauth.getValidatedIdTokenClaims(response)?.webid

    return typeof webId === "string" ? webId : undefined
}
