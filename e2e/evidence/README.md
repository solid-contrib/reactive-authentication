# Evidence tests for reactive-authentication PR review threads

Behavioural-evidence Playwright tests backing the answers posted to PR review
threads — chiefly @langsamu's PR #13 question *"Is it correct to start with
`prompt=none`? … Some [servers] require interaction, others don't."*

They run against **real** Solid authorization servers with **no credentials**
(dynamic client registration + an unauthenticated `prompt=none` request is enough
to observe each server's silent-auth behaviour).

## Run

```sh
cd e2e/evidence
npm install
npx playwright install chromium
npm test
```

## Specs

- `discovery.spec.ts` — records the discovery fields the provider keys off
  (`grant_types_supported`/refresh_token, `scopes_supported`/offline_access,
  PKCE, DPoP algs) for CSS, ESS, and the solid-test broker.
- `prompt-none.spec.ts` — sends an unauthenticated `prompt=none` auth request
  (PKCE, scope `openid webid`) and asserts each server declines with one of the
  three OIDC interaction errors the provider/UI retry on. **This is the core
  evidence for the PR #13 question.**
- `warm-session.spec.ts` — the other half (an existing AS session makes
  `prompt=none` succeed silently). **Skipped**: needs an interactive human login,
  not available to an autonomous run. Scaffolding left in place.

## Observed results (2026-06-12)

| Server | cold `prompt=none` (no session) → |
| --- | --- |
| solidcommunity.net (CSS) | `error=interaction_required` ("An account cookie is required.") |
| login.inrupt.com (ESS)   | `error=interaction_required` ("Interaction required to proceed") |
| idp.solid-test.jeswr.org (broker) | `error=login_required` ("End-User authentication is required") |

All three are handled by `AuthorizationCodeFlow#needsInteraction` /
`DPoPTokenProvider#authenticate`, which retry interactively on
`login_required` | `interaction_required` | `consent_required`.
