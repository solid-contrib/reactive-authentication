import { test, expect } from "@playwright/test"
import { MATRIX, silentAttempt, INTERACTION_ERRORS } from "./oidc.js"

/**
 * EVIDENCE (BROADENED) for PR #13, @langsamu's review comment:
 *
 *   "Is it correct to start with `prompt=none`? I see differences between the
 *    authorization servers: Some require interaction, others don't."
 *
 * prompt-none.spec.ts answered this against 3 servers. This matrix variant broadens the
 * evidence to ALL known Solid server CODEBASES (one live endpoint each where one exists):
 * CSS, Pivot, ESS, NSS, Trinpod, plus a local full-control CSS, with Manas + the pdsinterop
 * PHP server recorded as unverified (no reachable public IdP).
 *
 * The point is NOT to force every server into the same answer — it is to RECORD, per
 * codebase, what a session-less prompt=none actually does and whether it lands in the
 * library's retry set {login_required, interaction_required, consent_required}. Two
 * codebases (NSS, Trinpod) DIVERGE: they ignore prompt=none and serve an interactive HTML
 * login page instead of an OIDC error redirect. That divergence is asserted-and-recorded,
 * not failed — it is exactly the kind of difference Samu asked about, and it is flagged in
 * the PR follow-up as a possible gap in the library's retry classification.
 *
 * Credential-free: a dynamically-registered public client + an unauthenticated prompt=none
 * request. Unreachable / no-public-IdP entries are skipped with a recorded reason.
 */
for (const entry of MATRIX) {
    const title = `[${entry.codebase}] ${entry.id} (${entry.issuer ?? "no public IdP"})`

    if (!entry.issuer) {
        // No reachable public OIDC endpoint for this codebase — record and skip, don't fail.
        test.skip(`prompt=none — ${title} :: ${entry.note ?? "unverified"}`, () => {})
        continue
    }

    test(`prompt=none — ${title}`, async ({ request }) => {
        let result: Awaited<ReturnType<typeof silentAttempt>>
        try {
            result = await silentAttempt(request, entry.issuer as string)
        } catch (e) {
            // Host unreachable / registration failed at runtime: skip with the reason recorded.
            test.skip(true, `unreachable at runtime: ${(e as Error).message}`)
            return
        }

        const inRetrySet =
            result.kind === "interaction-error" && (INTERACTION_ERRORS as readonly string[]).includes(result.error ?? "")

        console.log(
            `\n[${entry.codebase}] ${entry.issuer}` +
                `\n  kind=${result.kind} status=${result.status} error=${result.error} in_retry_set=${inRetrySet}` +
                `\n  error_description=${result.errorDescription}` +
                `\n  content_type=${result.contentType} final=${result.finalUrl}` +
                (entry.note ? `\n  note: ${entry.note}` : ""),
        )

        // Never a silent code without a session, on any codebase.
        expect(result.code, "no code should be issued for a session-less prompt=none").toBe(false)

        if (entry.expect === "interaction-error") {
            // Conformant case: redirect to callback with one of the three retry errors.
            expect(result.kind, "should redirect to callback with an OIDC error").toBe("interaction-error")
            expect(
                INTERACTION_ERRORS as readonly string[],
                `prompt=none should yield an interaction error (got ${result.error})`,
            ).toContain(result.error)
        } else if (entry.expect === "html-login") {
            // Recorded divergence: NSS / Trinpod ignore prompt=none and show an HTML login.
            // We assert the observed shape so a future change (e.g. them starting to honour
            // prompt=none) surfaces as a test change rather than going unnoticed — but we do
            // NOT treat it as a failure of the strategy.
            expect(
                result.kind,
                `${entry.codebase} is recorded as ignoring prompt=none → HTML login (no OIDC error redirect)`,
            ).toBe("html-login")
            expect(inRetrySet, "this codebase does NOT produce a retry-set error").toBe(false)
        }
    })
}
