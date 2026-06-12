import { test, expect } from "@playwright/test"
import { MATRIX, discover } from "./oidc.js"

/**
 * EVIDENCE (BROADENED): cross-CODEBASE OIDC discovery metadata.
 *
 * discovery.spec.ts records the fields the provider keys off for 3 servers. This matrix
 * variant records the same fields across every reachable Solid server codebase, so the
 * PR #13 follow-up table (PKCE / offline_access / DPoP / refresh_token per codebase) is
 * grounded in observed discovery docs.
 *
 * Unlike the original spec this one does NOT assert a uniform feature set — the whole point
 * is that codebases differ. It records facts and only asserts the minimum every advertised
 * discovery doc must have (an authorization_endpoint), so divergent-but-honest servers
 * (NSS without PKCE/DPoP, Trinpod without offline_access) are reported, not failed.
 * Unreachable / no-public-IdP entries are skipped with a recorded reason.
 */
for (const entry of MATRIX) {
    const title = `[${entry.codebase}] ${entry.id} (${entry.issuer ?? "no public IdP"})`

    if (!entry.issuer) {
        test.skip(`discovery — ${title} :: ${entry.note ?? "unverified"}`, () => {})
        continue
    }

    test(`discovery — ${title}`, async ({ request }) => {
        let d: Awaited<ReturnType<typeof discover>>
        try {
            d = await discover(request, entry.issuer as string)
        } catch (e) {
            test.skip(true, `unreachable at runtime: ${(e as Error).message}`)
            return
        }

        const facts = {
            issuer: d.issuer,
            token_endpoint_auth_methods_supported: d.token_endpoint_auth_methods_supported,
            "public client (token_endpoint_auth_method=none)":
                d.token_endpoint_auth_methods_supported?.includes("none") ?? false,
            code_challenge_methods_supported: d.code_challenge_methods_supported,
            "PKCE S256": d.code_challenge_methods_supported?.includes("S256") ?? false,
            scopes_supported: d.scopes_supported,
            "offline_access advertised": d.scopes_supported?.includes("offline_access") ?? false,
            dpop_signing_alg_values_supported: d.dpop_signing_alg_values_supported,
            "DPoP advertised": (d.dpop_signing_alg_values_supported?.length ?? 0) > 0,
            "DPoP ES256 (the key the provider generates)":
                d.dpop_signing_alg_values_supported?.includes("ES256") ?? false,
            grant_types_supported: d.grant_types_supported,
            "refresh_token grant": d.grant_types_supported?.includes("refresh_token") ?? false,
            prompt_values_supported: d.prompt_values_supported ?? "(not advertised)",
            has_registration_endpoint: typeof d.registration_endpoint === "string",
        }
        console.log(`\n[${entry.codebase}] ${entry.issuer}\n${JSON.stringify(facts, null, 2)}`)

        // The only universal assertion: a usable discovery doc names an authorization endpoint.
        expect(typeof d.authorization_endpoint, "authorization_endpoint present").toBe("string")
    })
}
