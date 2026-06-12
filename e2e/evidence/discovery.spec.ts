import { test, expect } from "@playwright/test"
import { SERVERS, discover } from "./oidc.js"

/**
 * EVIDENCE: cross-server OIDC discovery metadata.
 *
 * Supports the prompt=none answer (PR #13) and the refresh-token / offline_access
 * answers (PR #11, #12): the provider keys its behaviour off `grant_types_supported`
 * (refresh_token) and `scopes_supported` (offline_access), and the popup retry off
 * `code_challenge_methods_supported` (PKCE). This test records, for each real server,
 * exactly the fields the code inspects — so the thread answers cite observed metadata.
 */

for (const [name, issuer] of Object.entries(SERVERS)) {
    test(`discovery metadata the provider keys off [${name}: ${issuer}]`, async ({ request }) => {
        const d = await discover(request, issuer)

        const facts = {
            issuer: d.issuer,
            grant_types_supported: d.grant_types_supported,
            "supports refresh_token": d.grant_types_supported?.includes("refresh_token") ?? false,
            scopes_supported: d.scopes_supported,
            "advertises offline_access": d.scopes_supported?.includes("offline_access") ?? false,
            code_challenge_methods_supported: d.code_challenge_methods_supported,
            "requires/supports PKCE S256": d.code_challenge_methods_supported?.includes("S256") ?? false,
            dpop_signing_alg_values_supported: d.dpop_signing_alg_values_supported,
            "supports ES256 DPoP (the key the provider generates)":
                d.dpop_signing_alg_values_supported?.includes("ES256") ?? false,
            token_endpoint_auth_methods_supported: d.token_endpoint_auth_methods_supported,
            has_registration_endpoint: typeof d.registration_endpoint === "string",
        }
        console.log(`\n[${name}] ${issuer}\n${JSON.stringify(facts, null, 2)}`)

        // Every server we target supports dynamic registration and the auth-code grant.
        expect(typeof d.registration_endpoint, "registration_endpoint present").toBe("string")
        expect(d.grant_types_supported, "authorization_code supported").toContain("authorization_code")

        // All three advertise refresh_token + offline_access — the basis for PR #11/#12.
        expect(d.grant_types_supported, "refresh_token grant advertised").toContain("refresh_token")
        expect(d.scopes_supported, "offline_access scope advertised").toContain("offline_access")
    })
}
