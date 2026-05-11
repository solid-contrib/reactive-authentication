import { ReactiveAuthenticationClient } from "./ReactiveAuthenticationClient.js"
import { DPoPTokenProvider } from "./DPoPTokenProvider.js"
import { BearerTokenProvider } from "./BearerTokenProvider.js"

console.debug("reactive-fetch-worker.js")

self.addEventListener("install", onInstall)
self.addEventListener("activate", onActivate)
self.addEventListener("fetch", onFetch)

function onInstall(e) {
    e.waitUntil(self.skipWaiting())
}

function onActivate(e) {
    e.waitUntil(self.clients.claim())
}

function onFetch(e) {
    if (!isFetch(e)) return

    e.respondWith(upgrade(e))
}

async function upgrade(e) {
    const client = await self.clients.get(e.clientId)

    const dPoPTokenProvider = new DPoPTokenProvider
    const bearerProvider = new BearerTokenProvider

    dPoPTokenProvider.addEventListener("codeRequired", async e => e.resolve(await postEventAndWait(e, client)))
    bearerProvider.addEventListener("codeRequired", async e => e.resolve(await postEventAndWait(e, client)))

    return new ReactiveAuthenticationClient(self.fetch, [bearerProvider, dPoPTokenProvider]).fetch(e.request)
}

function postEventAndWait(e, client) {
    return new Promise(resolve => {
        const channel = new MessageChannel()

        channel.port1.onmessage = e => resolve(e.data)

        client.postMessage({type: e.type, detail: e.detail}, [channel.port2])
    })
}

function isFetch(e) {
    return e.request.destination === ""
}
