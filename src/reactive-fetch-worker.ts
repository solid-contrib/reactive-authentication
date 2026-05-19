import { ReactiveAuthenticationClient } from "./ReactiveAuthenticationClient.js"
import { DPoPTokenProvider } from "./DPoPTokenProvider.js"
import { BearerTokenProvider } from "./BearerTokenProvider.js"

declare const self: ServiceWorkerGlobalScope

console.debug("reactive-fetch-worker.js")

self.addEventListener("install", onInstall)
self.addEventListener("activate", onActivate)
self.addEventListener("fetch", onFetch)

function onInstall(e: ExtendableEvent): void {
    e.waitUntil(self.skipWaiting())
}

function onActivate(e: ExtendableEvent): void {
    e.waitUntil(self.clients.claim())
}

async function onFetch(e: FetchEvent): Promise<void> {
    if (!isFetch(e)) return

    const client = await self.clients.get(e.clientId)
    if (client === undefined) return

    e.respondWith(upgrade(e.request, client))
}

function upgrade(request: Request, client: Client): Promise<Response> {
    const dPoPTokenProvider = new DPoPTokenProvider(postEventAndWait.bind(undefined, client))
    const bearerProvider = new BearerTokenProvider(postEventAndWait.bind(undefined, client))

    return new ReactiveAuthenticationClient(self.fetch, [bearerProvider, dPoPTokenProvider]).fetch(request)
}

function postEventAndWait(client: Client, e: URL): Promise<string> {
    const {promise, resolve} = Promise.withResolvers<string>()
    const channel = new MessageChannel()

    channel.port1.onmessage = e => resolve(e.data)

    client.postMessage(e.toString(), [channel.port2])

    return promise
}

function isFetch(e: FetchEvent): boolean {
    return e.request.destination === ""
}
