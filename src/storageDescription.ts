import * as oauth from "oauth4webapi"
import type {Cache} from "./Cache.js"
import {MemoryCache} from "./MemoryCache.js"
import {ReactiveAuthenticationError} from "./ReactiveAuthenticationError.js"

const cidContext = "https://www.w3.org/ns/cid/v1"
const lwsContext = "https://www.w3.org/ns/lws/v1"

/**
 * Finds the storage root of a storage, as needed for {@link https://w3c.github.io/lws-protocol/lws10-oauth/#authorization-discovery-validation LWS10-OAUTH Authorization Discovery Validation}.
 */
export interface StorageRootProvider {
    getStorageRoot(storageUri: string, signal: AbortSignal): Promise<string>
}

/**
 * Gets the `serviceEndpoint` of the `StorageRoot` service from the storage description resource of a storage, as defined in {@link https://www.w3.org/TR/lws10-core/#storage-description-data-model LWS 1.0 Core Storage Description Data Model} and {@link https://www.w3.org/TR/lws10-core/#storage-description-services Storage Services}.
 *
 * The storage URI is requested with `Accept: application/cid`, the media type a storage description is serialized with in {@link https://www.w3.org/TR/lws10-core/#storage-description-representation LWS 1.0 Core Storage Description Representation}. Other representations are not requested, because the response is read as plain JSON.
 *
 * The response is read as JSON, not as RDF. The `@context` of a storage description MUST be an array that starts with `https://www.w3.org/ns/cid/v1` and `https://www.w3.org/ns/lws/v1`, so a compacted document with that context has fixed term definitions and its `service`, `type` and `serviceEndpoint` properties can be read directly. A response with a different `@context` is rejected instead of being expanded.
 *
 * A `type` that is a string or an array of strings is accepted, as the data model allows a string or a set of strings. A `serviceEndpoint` MUST be a URI, and so must be a string.
 *
 * @throws {ReactiveAuthenticationError} If the request fails, the response is not successful, is not valid JSON, has an unexpected `@context`, or has no `StorageRoot` service with a `serviceEndpoint`.
 */
export async function fetchStorageRoot(storageUri: string, signal: AbortSignal, options?: oauth.HttpRequestOptions<string, any>): Promise<string> {
    oauth.checkProtocol(new URL(storageUri), options?.[oauth.allowInsecureRequests] !== true)

    const fetchImplementation = options?.[oauth.customFetch] ?? fetch

    let response: Response
    try {
        response = await fetchImplementation(storageUri, {
            // The custom fetch type requires a body property.
            body: null,
            headers: {accept: "application/cid"},
            method: "GET",
            // The custom fetch type requires manual. The id of a storage description is its canonical URI, so a redirect is an error.
            redirect: "manual",
            signal,
        })
    } catch (error) {
        throw new ReactiveAuthenticationError(`Storage description of ${storageUri} could not be retrieved`, error)
    }

    if (!response.ok) {
        throw new ReactiveAuthenticationError(`Storage description of ${storageUri} could not be retrieved: HTTP ${response.status}`, response)
    }

    let description: unknown
    try {
        description = await response.json()
    } catch (error) {
        throw new ReactiveAuthenticationError(`Storage description of ${storageUri} is not valid JSON`, error)
    }

    if (!isRecord(description)) {
        throw new ReactiveAuthenticationError(`Storage description of ${storageUri} is not a JSON object`)
    }

    const context = description["@context"]
    if (!Array.isArray(context) || context[0] !== cidContext || context[1] !== lwsContext) {
        throw new ReactiveAuthenticationError(`Storage description of ${storageUri} does not have the required @context`)
    }

    const services = description.service
    const service = Array.isArray(services) ? services.find(isStorageRootService) : undefined
    if (service === undefined) {
        throw new ReactiveAuthenticationError(`Storage description of ${storageUri} has no StorageRoot service`)
    }

    if (typeof service.serviceEndpoint !== "string") {
        throw new ReactiveAuthenticationError(`StorageRoot service of ${storageUri} has no serviceEndpoint`)
    }

    return service.serviceEndpoint
}

function isRecord(value: unknown): value is Record<string, unknown> {
    return typeof value === "object" && value !== null && !Array.isArray(value)
}

function isStorageRootService(value: unknown): value is Record<string, unknown> {
    if (!isRecord(value)) {
        return false
    }

    const type = value.type
    return type === "StorageRoot" || Array.isArray(type) && type.includes("StorageRoot")
}

/**
 * Requests the storage description with {@link fetchStorageRoot}.
 */
export class LwsStorageRootProvider implements StorageRootProvider {
    readonly #options: oauth.HttpRequestOptions<string, any> | undefined

    constructor(options?: oauth.HttpRequestOptions<string, any>) {
        this.#options = options
    }

    getStorageRoot(storageUri: string, signal: AbortSignal): Promise<string> {
        return fetchStorageRoot(storageUri, signal, this.#options)
    }
}

/**
 * Keeps the storage root of each storage, keyed by the storage URI, so that a storage description is requested once. A client can cache a storage description, as stated in {@link https://w3c.github.io/lws-protocol/lws10-oauth/#authorization-discovery-validation LWS10-OAUTH Authorization Discovery Validation}.
 */
export class CachingStorageRootProvider implements StorageRootProvider {
    readonly #cache: Cache<string>
    readonly #original: StorageRootProvider

    /**
     * @param original The provider whose results are cached.
     * @param cache Where results are kept. Defaults to a new {@link MemoryCache} owned by this instance.
     */
    constructor(original: StorageRootProvider, cache: Cache<string> = new MemoryCache) {
        this.#original = original
        this.#cache = cache
    }

    async getStorageRoot(storageUri: string, signal: AbortSignal): Promise<string> {
        const cached = await this.#cache.getItem(storageUri)
        if (cached !== null) {
            return cached
        }

        const fresh = await this.#original.getStorageRoot(storageUri, signal)
        await this.#cache.setItem(storageUri, fresh)
        return fresh
    }
}
