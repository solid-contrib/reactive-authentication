import assert from "node:assert/strict"
import {createHash} from "node:crypto"
import {describe, it} from "node:test"
import * as oauth from "oauth4webapi"
import type {AuthorizationServerProvider} from "../src/AuthorizationServerProvider.js"
import {ReactiveAuthenticationError} from "../src/ReactiveAuthenticationError.js"
import type {SubjectToken, SubjectTokenProvider} from "../src/SubjectTokenProvider.js"
import type {TokenExchangeTarget, TokenExchangeTargetProvider} from "../src/TokenExchangeTargetProvider.js"
import {TokenExchangeTokenProvider} from "../src/TokenExchangeTokenProvider.js"

const requested = "https://storage.example/storage_1/photos/img.jpg"
const resource = "https://storage.example/storage_1"
const issuer = "https://authorization.example"
const tokenEndpoint = "https://authorization.example/token"

const unauthorized = () => new Response(null, {status: 401})

type Behavior = {
    tokenResponses?: (() => Response)[],
    expiresIn?: number | null,
    tokenType?: string,
    matches?: boolean,
    target?: (request: Request) => TokenExchangeTarget,
    dpopAlgs?: string[],
}

function setup(behavior: Behavior = {}) {
    const tokenRequests: {body: URLSearchParams, headers: Headers}[] = []
    const invalidated: SubjectToken[] = []
    let subjectCounter = 0
    let tokenCounter = 0

    const options = {
        [oauth.customFetch]: async (url: string, init: oauth.CustomFetchOptions<any, any>) => {
            assert.equal(url, tokenEndpoint)
            tokenRequests.push({body: new URLSearchParams(init.body as string), headers: new Headers(init.headers as HeadersInit)})

            const scripted = behavior.tokenResponses?.[tokenRequests.length - 1]
            if (scripted !== undefined) {
                return scripted()
            }

            return Response.json({
                access_token: `access-${++tokenCounter}`,
                token_type: behavior.tokenType ?? "Bearer",
                ...(behavior.expiresIn === null ? {} : {expires_in: behavior.expiresIn ?? 3600}),
                issued_token_type: "urn:ietf:params:oauth:token-type:access_token",
            })
        },
    }

    const targetProvider: TokenExchangeTargetProvider = {
        matches: () => behavior.matches ?? true,
        getTarget: async request => behavior.target?.(request) ?? {issuer, resource},
    }
    const subjectTokenProvider: SubjectTokenProvider = {
        async getSubjectToken() {
            return {token: `subject-${++subjectCounter}`, type: "urn:ietf:params:oauth:token-type:id_token"}
        },
        async invalidate(_, subjectToken) {
            invalidated.push(subjectToken)
        },
    }
    const asProvider: AuthorizationServerProvider = {
        async getAuthorizationServer(i) {
            return {issuer: i.href, token_endpoint: tokenEndpoint, ...(behavior.dpopAlgs && {dpop_signing_alg_values_supported: behavior.dpopAlgs})}
        },
    }

    const provider = new TokenExchangeTokenProvider(targetProvider, subjectTokenProvider, asProvider, options)

    return {provider, tokenRequests, invalidated}
}

const request = (url = requested) => new Request(url)

describe("TokenExchangeTokenProvider", () => {
    describe("matches", () => {
        it("delegates to the target provider", async () => {
            assert.equal(await setup({matches: true}).provider.matches(request(), unauthorized()), true)
            assert.equal(await setup({matches: false}).provider.matches(request(), unauthorized()), false)
        })
    })

    describe("upgrade", () => {
        it("sends exactly the four token exchange parameters and no client authentication", async () => {
            const {provider, tokenRequests} = setup()

            await provider.upgrade(request(), unauthorized())

            assert.equal(tokenRequests.length, 1)
            const {body, headers} = tokenRequests[0]!
            assert.deepEqual(Object.fromEntries(body), {
                grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
                resource,
                subject_token: "subject-1",
                subject_token_type: "urn:ietf:params:oauth:token-type:id_token",
            })
            assert.equal(headers.has("Authorization"), false)
        })

        it("presents the access token as a Bearer token", async () => {
            const {provider} = setup()

            const upgraded = await provider.upgrade(new Request(requested, {headers: {"X-Test": "1"}}), unauthorized())

            assert.equal(upgraded.headers.get("Authorization"), "Bearer access-1")
            assert.equal(upgraded.headers.get("X-Test"), "1")
            assert.equal(upgraded.url, requested)
        })

        it("accepts a Bearer token type in any case", async () => {
            const {provider} = setup({tokenType: "bearer"})

            const upgraded = await provider.upgrade(request(), unauthorized())

            assert.equal(upgraded.headers.get("Authorization"), "Bearer access-1")
        })

        it("rejects an unknown token type", async () => {
            const {provider} = setup({tokenType: "MAC", dpopAlgs: ["ES256"]})

            await assert.rejects(provider.upgrade(request(), unauthorized()), oauth.UnsupportedOperationError)
        })

        it("rejects a DPoP token type when the request had no DPoP", async () => {
            const {provider} = setup({tokenType: "DPoP"})

            await assert.rejects(provider.upgrade(request(), unauthorized()), ReactiveAuthenticationError)
        })

        it("reuses the cached token for the same resource", async () => {
            const {provider, tokenRequests} = setup()

            await provider.upgrade(request(), unauthorized())
            const second = await provider.upgrade(request(`${resource}/other.txt`), unauthorized())

            assert.equal(tokenRequests.length, 1)
            assert.equal(second.headers.get("Authorization"), "Bearer access-1")
        })

        it("exchanges again for a different resource", async () => {
            const {provider, tokenRequests} = setup({target: ({url}) => ({issuer, resource: `https://storage.example/${new URL(url).pathname.split("/")[1]}`})})

            await provider.upgrade(request(), unauthorized())
            await provider.upgrade(request("https://storage.example/storage_2/a.txt"), unauthorized())

            assert.deepEqual(tokenRequests.map(({body}) => body.get("resource")), ["https://storage.example/storage_1", "https://storage.example/storage_2"])
        })

        it("exchanges again when the token has expired", async () => {
            const {provider, tokenRequests} = setup({expiresIn: 10})

            await provider.upgrade(request(), unauthorized())
            const second = await provider.upgrade(request(), unauthorized())

            assert.equal(tokenRequests.length, 2)
            assert.equal(second.headers.get("Authorization"), "Bearer access-2")
        })

        it("exchanges again when the response has no expires_in", async () => {
            const {provider, tokenRequests} = setup({expiresIn: null})

            await provider.upgrade(request(), unauthorized())
            await provider.upgrade(request(), unauthorized())

            assert.equal(tokenRequests.length, 2)
        })

        it("shares one exchange between concurrent requests", async () => {
            const {provider, tokenRequests} = setup()

            await Promise.all([provider.upgrade(request(), unauthorized()), provider.upgrade(request(), unauthorized())])

            assert.equal(tokenRequests.length, 1)
        })

        it("discards the subject token and retries once on invalid_grant", async () => {
            const {provider, tokenRequests, invalidated} = setup({
                tokenResponses: [() => Response.json({error: "invalid_grant"}, {status: 400})],
            })

            const upgraded = await provider.upgrade(request(), unauthorized())

            assert.equal(upgraded.headers.get("Authorization"), "Bearer access-1")
            assert.deepEqual(invalidated.map(({token}) => token), ["subject-1"])
            assert.deepEqual(tokenRequests.map(({body}) => body.get("subject_token")), ["subject-1", "subject-2"])
        })

        it("discards the subject token and retries once on a 401 invalid_token", async () => {
            const {provider, tokenRequests, invalidated} = setup({
                tokenResponses: [() => Response.json({error: "invalid_token"}, {status: 401})],
            })

            await provider.upgrade(request(), unauthorized())

            assert.equal(invalidated.length, 1)
            assert.equal(tokenRequests.length, 2)
        })

        it("throws when the retry fails too", async () => {
            const failure = () => Response.json({error: "invalid_grant"}, {status: 400})
            const {provider, tokenRequests} = setup({tokenResponses: [failure, failure]})

            await assert.rejects(provider.upgrade(request(), unauthorized()), oauth.ResponseBodyError)
            assert.equal(tokenRequests.length, 2)
        })

        it("does not retry on another error", async () => {
            const {provider, tokenRequests, invalidated} = setup({
                tokenResponses: [() => Response.json({error: "invalid_request"}, {status: 400})],
            })

            await assert.rejects(provider.upgrade(request(), unauthorized()), oauth.ResponseBodyError)
            assert.equal(tokenRequests.length, 1)
            assert.equal(invalidated.length, 0)
        })

        describe("DPoP", () => {
            const decode = (jwt: string) => ({
                header: JSON.parse(Buffer.from(jwt.split(".")[0]!, "base64url").toString()),
                payload: JSON.parse(Buffer.from(jwt.split(".")[1]!, "base64url").toString()),
            })
            const nonceDemand = () => Response.json({error: "use_dpop_nonce"}, {status: 400, headers: {"DPoP-Nonce": "nonce-1"}})

            it("sends a DPoP proof with the token request when the server advertises DPoP", async () => {
                const {provider, tokenRequests} = setup({dpopAlgs: ["ES256"]})

                await provider.upgrade(request(), unauthorized())

                const {header, payload} = decode(tokenRequests[0]!.headers.get("DPoP")!)
                assert.equal(header.typ, "dpop+jwt")
                assert.equal(payload.htm, "POST")
                assert.equal(payload.htu, tokenEndpoint)
            })

            it("sends no DPoP proof when the server does not advertise DPoP", async () => {
                const {provider, tokenRequests} = setup()

                await provider.upgrade(request(), unauthorized())

                assert.equal(tokenRequests[0]!.headers.has("DPoP"), false)
            })

            it("presents a DPoP token with a proof bound to the token and the request", async () => {
                const {provider} = setup({dpopAlgs: ["ES256"], tokenType: "DPoP"})

                const upgraded = await provider.upgrade(new Request(requested, {method: "PUT"}), unauthorized())

                assert.equal(upgraded.headers.get("Authorization"), "DPoP access-1")
                const {payload} = decode(upgraded.headers.get("DPoP")!)
                assert.equal(payload.htm, "PUT")
                assert.equal(payload.htu, requested)
                assert.equal(payload.ath, createHash("sha256").update("access-1").digest("base64url"))
            })

            it("presents a Bearer token without a proof when the server returns Bearer", async () => {
                const {provider} = setup({dpopAlgs: ["ES256"], tokenType: "Bearer"})

                const upgraded = await provider.upgrade(request(), unauthorized())

                assert.equal(upgraded.headers.get("Authorization"), "Bearer access-1")
                assert.equal(upgraded.headers.has("DPoP"), false)
            })

            it("retries once with the nonce when the server demands one", async () => {
                const {provider, tokenRequests, invalidated} = setup({dpopAlgs: ["ES256"], tokenType: "DPoP", tokenResponses: [nonceDemand]})

                await provider.upgrade(request(), unauthorized())

                assert.equal(tokenRequests.length, 2)
                assert.equal(decode(tokenRequests[0]!.headers.get("DPoP")!).payload.nonce, undefined)
                assert.equal(decode(tokenRequests[1]!.headers.get("DPoP")!).payload.nonce, "nonce-1")
                assert.equal(invalidated.length, 0)
            })

            it("does not retry a second nonce demand", async () => {
                const {provider, tokenRequests} = setup({dpopAlgs: ["ES256"], tokenResponses: [nonceDemand, nonceDemand]})

                await assert.rejects(provider.upgrade(request(), unauthorized()))
                assert.equal(tokenRequests.length, 2)
            })

            it("reuses a cached DPoP token with a new proof for each request", async () => {
                const {provider, tokenRequests} = setup({dpopAlgs: ["ES256"], tokenType: "DPoP"})

                const first = await provider.upgrade(request(), unauthorized())
                const second = await provider.upgrade(request(`${resource}/other.txt`), unauthorized())

                assert.equal(tokenRequests.length, 1)
                assert.equal(second.headers.get("Authorization"), "DPoP access-1")
                assert.notEqual(second.headers.get("DPoP"), first.headers.get("DPoP"))
                assert.equal(decode(second.headers.get("DPoP")!).payload.htu, `${resource}/other.txt`)
            })
        })

        it("propagates a failure to find the target", async () => {
            const {provider, tokenRequests} = setup({target: () => { throw new ReactiveAuthenticationError("no target") }})

            await assert.rejects(provider.upgrade(request(), unauthorized()), ReactiveAuthenticationError)
            assert.equal(tokenRequests.length, 0)
        })
    })
})
