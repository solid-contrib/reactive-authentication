import { Events, OAuth2Server } from "oauth2-mock-server"

export interface FakeAuthorizationServer {
    readonly issuer: string
    fetch: typeof globalThis.fetch
    authorize(authorizationUrl: URL): Promise<string>
    readonly registrations: Record<string, unknown>[]
    close(): Promise<void>
}

const issuer = "https://as.test"

export async function createFakeAuthorizationServer(): Promise<FakeAuthorizationServer> {
    const nativeFetch = globalThis.fetch
    const registrations: Record<string, unknown>[] = []
    const server = new OAuth2Server()

    server.service.addRoute("POST", "/register", (request, response) => {
        const metadata = request.body as Record<string, unknown>
        registrations.push(metadata)
        response.writeHead(201, {"content-type": "application/json"})
        response.end(JSON.stringify({
            client_id: "client",
            redirect_uris: metadata.redirect_uris,
            response_types: ["code"],
            grant_types: ["authorization_code"],
            token_endpoint_auth_method: "none",
        }))
    })
    server.service.on(Events.BeforeResponse, response => {
        response.body.token_type = "DPoP"
    })

    await server.issuer.keys.generate("RS256")
    await server.start(0, "127.0.0.1")
    const upstream = `http://127.0.0.1:${server.address().port}`
    // Present HTTPS to oauth4webapi while keeping the test listener certificate-free.
    server.issuer.url = issuer

    async function fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
        const request = new Request(input, init)
        const source = new URL(request.url)
        if (source.origin !== issuer) {
            throw new Error(`Unexpected request to ${source.origin}`)
        }
        const target = new URL(`${source.pathname}${source.search}`, upstream)
        const body = request.method === "GET" || request.method === "HEAD" ? undefined : await request.arrayBuffer()
        const response = await nativeFetch(target, {
            method: request.method,
            headers: request.headers,
            body,
            redirect: request.redirect,
            signal: request.signal,
        })

        if (source.pathname === "/.well-known/openid-configuration") {
            return Response.json({...await response.json(), registration_endpoint: `${issuer}/register`})
        }
        return response
    }

    return {
        issuer,
        fetch,
        async authorize(authorizationUrl: URL): Promise<string> {
            const response = await fetch(new Request(authorizationUrl, {redirect: "manual"}))
            const redirect = response.headers.get("location")
            if (redirect === null) {
                throw new Error("Authorization server did not redirect")
            }
            return redirect
        },
        registrations,
        close: () => server.stop(),
    }
}
