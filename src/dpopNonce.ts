import * as oauth from "oauth4webapi"

export async function withDPoPNonceRetry<T>(send: () => Promise<T>): Promise<T> {
    try {
        return await send()
    } catch (e) {
        if (!oauth.isDPoPNonceError(e)) {
            throw e
        }

        return await send()
    }
}
