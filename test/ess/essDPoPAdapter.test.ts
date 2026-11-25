import assert from "node:assert/strict"
import {createHash} from "node:crypto"
import {describe, it} from "node:test"
import * as oauth from "oauth4webapi"
import {essDPoPAdapter} from "../../src/ess/essDPoPAdapter.js"

const tokenEndpoint = "https://authorization.example/token"
const authorizationServer: oauth.AuthorizationServer = {issuer: "https://authorization.example", token_endpoint: tokenEndpoint}
const client: oauth.Client = {client_id: "unused"}
const subjectToken = {token: "subject-1", type: "urn:ietf:params:oauth:token-type:id_token"}

const decode = (jwt: string) => JSON.parse(Buffer.from(jwt.split(".")[1]!, "base64url").toString())

async function sendTokenRequest(handle: oauth.DPoPHandle, response: () => Response = () => Response.json({})) {
    const proofs: string[] = []

    await oauth.genericTokenEndpointRequest(authorizationServer, client, () => {}, "urn:ietf:params:oauth:grant-type:token-exchange", {}, {
        DPoP: handle,
        [oauth.customFetch]: async (_: string, init: oauth.CustomFetchOptions<any, any>) => {
            proofs.push(new Headers(init.headers as HeadersInit).get("DPoP")!)
            return response()
        },
    })

    return proofs
}

describe("essDPoPAdapter", () => {
    it("adds ath over the subject token to the token request proof", async () => {
        const handle = essDPoPAdapter(oauth.DPoP(client, await oauth.generateKeyPair("ES256")), subjectToken)

        const [proof] = await sendTokenRequest(handle)

        const payload = decode(proof!)
        assert.equal(payload.ath, createHash("sha256").update(subjectToken.token).digest("base64url"))
        assert.equal(payload.htm, "POST")
        assert.equal(payload.htu, tokenEndpoint)
    })

    it("keeps the nonce handling of oauth4webapi", async () => {
        const handle = essDPoPAdapter(oauth.DPoP(client, await oauth.generateKeyPair("ES256")), subjectToken)

        await sendTokenRequest(handle, () => Response.json({}, {headers: {"DPoP-Nonce": "nonce-1"}}))
        const [proof] = await sendTokenRequest(handle)

        const payload = decode(proof!)
        assert.equal(payload.nonce, "nonce-1")
        assert.ok(payload.ath)
    })
})
