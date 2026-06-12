import { test, expect } from "@playwright/test"
import { SERVERS, silentAttempt } from "./oidc.js"

/**
 * EVIDENCE (HONEST GAP) for PR #13, @langsamu point 3 — the OTHER half of the answer.
 *
 * prompt=none is the OIDC "silent authentication" pattern: when the user ALREADY has
 * an active session at the AS, prompt=none returns a code with NO interaction; when
 * they do not, it returns an interaction error and the provider retries interactively.
 *
 * The cold (no-session) half is proven deterministically in prompt-none.spec.ts.
 * The WARM (existing-session → silent success) half requires a real authenticated
 * browser session at each AS, which means an INTERACTIVE HUMAN LOGIN with credentials
 * this autonomous run does not have. So it is intentionally skipped rather than faked.
 *
 * To complete this evidence manually: log in to the AS in the Playwright browser
 * context first (or load a storageState with the AS session cookie), then assert that
 * silentAttempt(...) returns { code: true, error: null }. The scaffolding is below.
 */
test.describe("warm session: prompt=none returns a code silently when a session exists", () => {
    for (const [name, issuer] of Object.entries(SERVERS)) {
        test.skip(`[${name}: ${issuer}] needs an interactive logged-in AS session (not available autonomously)`, async ({ request }) => {
            // Pre-req (manual): an authenticated session cookie for `issuer` must be present.
            const result = await silentAttempt(request, issuer)
            expect(result.code, "with an active AS session prompt=none yields a code").toBe(true)
            expect(result.error).toBeNull()
        })
    }
})
