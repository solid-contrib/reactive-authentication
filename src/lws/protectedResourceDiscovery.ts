import * as oauth from "oauth4webapi"
import {findLinkTarget} from "../linkHeader.js"
import {parseChallenges} from "../parseChallenges.js"
import {ReactiveAuthenticationError} from "../ReactiveAuthenticationError.js"
import type {StorageRootProvider} from "./storageDescription.js"

const storageRel = "https://www.w3.org/ns/lws#storage"

/**
 * Discovers the authorization server and the storage of a protected resource from a 401 response, and validates them as required by {@link https://w3c.github.io/lws-protocol/lws10-oauth/#authorization-server-discovery LWS10-OAUTH Authorization Server Discovery}, {@link https://w3c.github.io/lws-protocol/lws10-oauth/#protected-resource-metadata Protected Resource Metadata} and {@link https://w3c.github.io/lws-protocol/lws10-oauth/#authorization-discovery-validation Discovery Validation by a Client}.
 *
 * The requested URI is the `url` of the response. The first `Bearer` or `DPoP` challenge with a `resource_metadata` parameter, defined in {@link https://www.rfc-editor.org/rfc/rfc9728#section-5.1 RFC 9728 § 5.1}, is used. Without such a challenge this function returns `undefined`, so that the caller can try the legacy `as_uri` and `realm` challenge. With such a challenge, every failure throws: the server has declared that it implements the current specification, and falling back to the legacy path would bypass the validation checks.
 *
 * The protected resource metadata is requested from the `resource_metadata` URL itself, and not from a URL derived as in {@link https://www.rfc-editor.org/rfc/rfc9728#section-3.1 RFC 9728 § 3.1}, because LWS10-OAUTH supplies the URL. The response is validated with `oauth.processResourceDiscoveryResponse`. The `resource` value is additionally compared as an exact string with the requested URI, because LWS10-OAUTH requires the values to be identical and `oauth.processResourceDiscoveryResponse` compares them after URL normalization. The first entry of `authorization_servers`, which LWS10-OAUTH makes REQUIRED, is the issuer.
 *
 * The storage is the target of the `https://www.w3.org/ns/lws#storage` link relation, as defined in {@link https://www.w3.org/TR/lws10-core/#x5-1-2-discovery-and-binding LWS 1.0 Core § 5.1.2 Discovery and Binding}. It is the `resource` for the token request.
 *
 * The checks of LWS10-OAUTH Discovery Validation by a Client are that the `resource_metadata` URL and the `serviceEndpoint` of the storage root have the same scheme and authority as the requested URI, and that the metadata `resource` is identical to it.
 *
 * @param response The 401 response to the request for the protected resource.
 * @param storageRootProvider Finds the storage root of the storage.
 * @returns The issuer and the storage, or `undefined` if the response has no challenge with `resource_metadata`.
 * @throws {ReactiveAuthenticationError} If the challenge has an invalid `resource_metadata` or a check fails, the metadata cannot be retrieved or is invalid, the response has no storage link, or the storage root cannot be found.
 */
export async function discoverProtectedResource(response: Response, storageRootProvider: StorageRootProvider, signal: AbortSignal, options?: oauth.HttpRequestOptions<string, any>): Promise<{issuer: string, resource: string} | undefined> {
    const challenge = parseChallenges(response.headers.get("WWW-Authenticate"))
        .find(candidate => (candidate.scheme === "bearer" || candidate.scheme === "dpop") && candidate.parameters.resource_metadata !== undefined)
    if (challenge === undefined) {
        return undefined
    }

    const requestUri = response.url
    const requestUrl = URL.parse(requestUri)
    if (requestUrl === null) {
        throw new ReactiveAuthenticationError("The response does not have a requested URI")
    }

    const metadataUri = challenge.parameters.resource_metadata!
    const metadataUrl = URL.parse(metadataUri, requestUri)
    if (metadataUrl === null) {
        throw new ReactiveAuthenticationError(`The resource_metadata ${metadataUri} of ${requestUri} is not a URL`)
    }

    if (!hasSameOrigin(metadataUrl, requestUrl)) {
        throw new ReactiveAuthenticationError(`The resource_metadata ${metadataUrl.href} does not have the same scheme and authority as ${requestUri}`)
    }

    oauth.checkProtocol(metadataUrl, options?.[oauth.allowInsecureRequests] !== true)

    const fetchImplementation = options?.[oauth.customFetch] ?? fetch

    let metadataResponse: Response
    try {
        metadataResponse = await fetchImplementation(metadataUrl.href, {
            // The custom fetch type requires a body property.
            body: null,
            headers: {accept: "application/json"},
            method: "GET",
            // The custom fetch type requires manual. The metadata URL is supplied by the server, so a redirect is an error.
            redirect: "manual",
            signal,
        })
    } catch (error) {
        throw new ReactiveAuthenticationError(`Protected resource metadata of ${requestUri} could not be retrieved`, error)
    }

    let metadata: oauth.ResourceServer
    try {
        metadata = await oauth.processResourceDiscoveryResponse(requestUrl, metadataResponse)
    } catch (error) {
        throw new ReactiveAuthenticationError(`Protected resource metadata of ${requestUri} is not valid`, error)
    }

    // oauth.processResourceDiscoveryResponse normalizes both values as URLs, but LWS10-OAUTH requires them to be identical.
    if (metadata.resource !== requestUri) {
        throw new ReactiveAuthenticationError(`The resource ${metadata.resource} of the protected resource metadata is not identical to ${requestUri}`)
    }

    const servers: unknown = metadata.authorization_servers
    const issuer: unknown = Array.isArray(servers) ? servers[0] : undefined
    if (!Array.isArray(servers) || typeof issuer !== "string" || !servers.every(server => typeof server === "string")) {
        throw new ReactiveAuthenticationError(`Protected resource metadata of ${requestUri} does not have a non-empty authorization_servers array of strings`)
    }

    const storageUri = findLinkTarget(response, storageRel)
    if (storageUri === undefined) {
        throw new ReactiveAuthenticationError(`The response for ${requestUri} has no Link header with rel ${storageRel}`)
    }

    const storageRoot = await storageRootProvider.getStorageRoot(storageUri, signal)
    const storageRootUrl = URL.parse(storageRoot)
    if (storageRootUrl === null || !hasSameOrigin(storageRootUrl, requestUrl)) {
        throw new ReactiveAuthenticationError(`The storage root ${storageRoot} of ${storageUri} does not have the same scheme and authority as ${requestUri}`)
    }

    return {issuer, resource: storageUri}
}

function hasSameOrigin(a: URL, b: URL): boolean {
    return a.protocol === b.protocol && a.host === b.host
}
