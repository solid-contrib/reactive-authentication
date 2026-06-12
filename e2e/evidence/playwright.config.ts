import { defineConfig } from "@playwright/test"

/**
 * Evidence suite for reactive-authentication PR review threads.
 *
 * These are *behavioural-evidence* tests, not product tests: each spec asserts a
 * concrete fact about how real Solid authorization servers behave, so that answers
 * posted to review threads (esp. @langsamu's PR #13 "is it correct to start with
 * prompt=none?" question) are grounded in observed behaviour rather than guesswork.
 *
 * They run against PUBLIC discovery/authorization endpoints and need NO credentials:
 * a dynamically-registered client + an unauthenticated `prompt=none` request is
 * enough to observe each server's silent-auth behaviour. Tests that would need an
 * interactive human login are deliberately NOT attempted (see the notes in the specs).
 */
export default defineConfig({
    testDir: ".",
    fullyParallel: true,
    reporter: [["list"], ["json", { outputFile: "results.json" }]],
    timeout: 60_000,
    use: {
        // No baseURL: each test targets a different issuer explicitly.
        ignoreHTTPSErrors: false,
    },
})
