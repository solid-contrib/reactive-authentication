import * as oauth from "oauth4webapi"
import {parseChallenges} from "../parseChallenges.js"
import {ReactiveAuthenticationError} from "../ReactiveAuthenticationError.js"
import type {TokenExchangeTarget, TokenExchangeTargetProvider} from "../TokenExchangeTargetProvider.js"
import {findLegacyLwsChallenge, isWithinRealm} from "./legacyLwsChallenge.js"
import {discoverProtectedResource} from "./protectedResourceDiscovery.js"
import type {StorageRootProvider} from "./storageDescription.js"

/**
 * Finds the authorization server and the storage of a request from its 401 response, as defined in {@link https://w3c.github.io/lws-protocol/lws10-oauth/#authorization-server-discovery LWS10-OAUTH Authorization Server Discovery}.
 *
 * The current discovery, with the `resource_metadata` challenge parameter, is used when the challenge has it ({@link discoverProtectedResource}). Otherwise the legacy `as_uri` and `realm` challenge of {@link https://www.w3.org/TR/2026/WD-lws10-core-20260331/#x5-2-1-authorization-server-discovery LWS 1.0 Core § 5.2.1 Authorization Server Discovery} is used, and the `realm` is the `resource`. A challenge with `resource_metadata` never falls back to the legacy challenge.
 */
export class LwsTokenExchangeTargetProvider implements TokenExchangeTargetProvider {
    readonly #storageRootProvider: StorageRootProvider
    readonly #options: oauth.HttpRequestOptions<string, any> | undefined

    /**
     * @param storageRootProvider Finds the storage root, for the validation of the discovered storage.
     * @param options HTTP options for the discovery requests, for example to allow plain HTTP (see `allowInsecureRequests`).
     */
    constructor(storageRootProvider: StorageRootProvider, options?: oauth.HttpRequestOptions<string, any>) {
        this.#storageRootProvider = storageRootProvider
        this.#options = options
    }

    matches(request: Request, response: Response): boolean {
        const challenges = parseChallenges(response.headers.get("WWW-Authenticate"))

        const hasResourceMetadata = challenges.some(({scheme, parameters}) =>
            (scheme === "bearer" || scheme === "dpop") && parameters.resource_metadata !== undefined)
        if (hasResourceMetadata) {
            return true
        }

        const legacy = findLegacyLwsChallenge(challenges)

        return legacy !== undefined && isWithinRealm(new URL(request.url), legacy.realm)
    }

    async getTarget(request: Request, response: Response, signal: AbortSignal): Promise<TokenExchangeTarget> {
        const discovered = await discoverProtectedResource(response, this.#storageRootProvider, signal, this.#options)
        if (discovered !== undefined) {
            return discovered
        }

        const legacy = findLegacyLwsChallenge(parseChallenges(response.headers.get("WWW-Authenticate")))
        if (legacy === undefined || !isWithinRealm(new URL(request.url), legacy.realm)) {
            throw new ReactiveAuthenticationError(`The response for ${request.url} does not identify an authorization server and a storage`)
        }

        return {issuer: legacy.asUri, resource: legacy.realm}
    }
}
