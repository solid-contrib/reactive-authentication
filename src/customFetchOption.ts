import * as oauth from "oauth4webapi"

/**
 * Adapts an optional Fetch API implementation to oauth4webapi's `customFetch`
 * request option, as a spreadable options fragment.
 *
 * @remarks
 * Returns an empty fragment when no fetch is given, preserving oauth4webapi's
 * default (`globalThis.fetch`, resolved at call time).
 *
 * @see {@link TokenProviderOptions.fetch}
 */
export function customFetchOption(fetchImplementation: typeof globalThis.fetch | undefined): {[oauth.customFetch]?: (url: string, options: oauth.CustomFetchOptions<string, string | URLSearchParams | undefined>) => Promise<Response>} {
    if (fetchImplementation === undefined) {
        return {}
    }

    return {
        [oauth.customFetch]: (url, options) => fetchImplementation(url, {
            method: options.method,
            headers: options.headers,
            body: options.body ?? null,
            redirect: options.redirect,
            signal: options.signal ?? null,
        }),
    }
}
