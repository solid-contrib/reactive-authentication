import { test, expect } from "@playwright/test"
import { SERVERS, silentAttempt, INTERACTION_ERRORS } from "./oidc.js"

/**
 * EVIDENCE for PR #13, @langsamu's review comment, point 3:
 *
 *   "Is it correct to start with `prompt=none`? I see differences between the
 *    authorization servers: Some require interaction, others don't."
 *
 * What the code does (src/DPoPTokenProvider.ts#authenticate on feat/refresh-tokens):
 *   - The FIRST authorization request always carries `prompt=none` (a silent attempt).
 *   - If the AS answers with login_required / interaction_required / consent_required,
 *     the provider RETRIES interactively (dropping prompt, or prompt=consent when
 *     opting into offline_access). AuthorizationCodeFlow#needsInteraction keeps the
 *     popup open across exactly that retry.
 *
 * Claim under test: starting with prompt=none is correct, and the per-server
 * "differences" Samu observed are EXPECTED and HANDLED — with no active AS session,
 * every server declines the silent attempt with one of the three interaction errors;
 * the only difference is WHICH of the three string it uses.
 *
 * These probes send no cookies (no active session), so they demonstrate the
 * "cold" (must-interact) branch deterministically. The "warm" branch (an existing
 * AS session lets prompt=none return a code silently) needs a logged-in browser
 * session and is therefore NOT exercised here — see warm-session.spec.ts.
 */

for (const [name, issuer] of Object.entries(SERVERS)) {
    test(`prompt=none with no session → an interaction error the provider retries on [${name}: ${issuer}]`, async ({ request }) => {
        const result = await silentAttempt(request, issuer)

        console.log(`\n[${name}] ${issuer}`)
        console.log(`  status=${result.status} error=${result.error} code=${result.code}`)
        console.log(`  error_description=${result.errorDescription}`)

        // No code is silently issued without a session.
        expect(result.code, "no code should be issued for a session-less prompt=none").toBe(false)

        // The error is one of exactly the three the provider/UI retry interactively on.
        expect(
            INTERACTION_ERRORS as readonly string[],
            `prompt=none should yield an interaction error (got ${result.error})`,
        ).toContain(result.error)
    })
}
