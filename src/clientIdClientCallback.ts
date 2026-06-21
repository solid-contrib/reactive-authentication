import type {GetClientCallback} from "./GetClientCallback.js"

export function clientIdClientCallback(clientIdDocUri: URL): GetClientCallback {
    return async function (_, __, signal) {
        return await (await fetch(clientIdDocUri, {signal})).json()
    }
}
