import assert from "node:assert/strict"
import {describe, it} from "node:test"
import * as oauth from "oauth4webapi"
import {DiscoveryAuthorizationServerProvider} from "../src/DiscoveryAuthorizationServerProvider.js"

function requestedUrls(algorithm?: "oidc" | "oauth2", issuer = "https://as.example/tenant"): Promise<string[]> {
    const urls: string[] = []
    const options = {
        [oauth.customFetch]: async (url: string) => {
            urls.push(url)
            return Response.json({issuer})
        },
    }
    const provider = algorithm === undefined
        ? new DiscoveryAuthorizationServerProvider(options)
        : new DiscoveryAuthorizationServerProvider(options, algorithm)

    return provider.getAuthorizationServer(new URL(issuer), new AbortController().signal).then(() => urls)
}

describe("DiscoveryAuthorizationServerProvider", () => {
    it("uses the OpenID Connect path by default", async () => {
        assert.deepEqual(await requestedUrls(), ["https://as.example/tenant/.well-known/openid-configuration"])
    })

    it("uses the RFC 8414 path with the oauth2 algorithm", async () => {
        assert.deepEqual(await requestedUrls("oauth2"), ["https://as.example/.well-known/oauth-authorization-server/tenant"])
    })
})
