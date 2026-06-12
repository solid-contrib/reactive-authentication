import { createHash, randomBytes } from "node:crypto"
import type { APIRequestContext } from "@playwright/test"

/**
 * The Solid authorization servers exercised as evidence for PR #13.
 *
 * The original three (css/ess/broker) are kept verbatim for back-compat with the
 * existing specs; MATRIX (below) is the broadened, codebase-tagged set the maintainer
 * asked for — one live endpoint per DISTINCT server codebase the reactive-fetch sample
 * app could target (the sample app is server-agnostic: the user types their issuer at
 * runtime, so the target set is "all known Solid IdPs").
 */
export const SERVERS = {
    /** Community Solid Server instance (oidc-provider based). */
    css: "https://solidcommunity.net",
    /** Enterprise Solid Server (Inrupt PodSpaces). */
    ess: "https://login.inrupt.com",
    /** The solid-test broker (Keycloak-fronted oidc-provider style broker). */
    broker: "https://idp.solid-test.jeswr.org",
} as const

/**
 * How a server is expected to answer a session-less `prompt=none` authorize request.
 *
 *  - "interaction-error": redirects to the callback with one of INTERACTION_ERRORS
 *    (the contract the library's retry classifier assumes). This is the conformant case.
 *  - "html-login": IGNORES prompt=none and serves an interactive HTML login page (HTTP 200,
 *    no callback redirect, no OIDC error). The library's error-string classifier never fires.
 *    This is the divergence @langsamu asked about — recorded, not hidden.
 *  - "unverified": no reachable public OIDC endpoint for this codebase; documented, skipped.
 */
export type PromptNoneClass = "interaction-error" | "html-login" | "unverified"

export interface MatrixEntry {
    /** Stable id used in the test title. */
    id: string
    /** The live issuer/IdP endpoint, or null when there is no reachable public instance. */
    issuer: string | null
    /** The DISTINCT server codebase this endpoint runs. */
    codebase: string
    /** A human note for the evidence table / honest-gap reporting. */
    note?: string
    /**
     * Best-known expected prompt=none class, used only to keep the assertion tolerant
     * (we never FAIL a recorded-divergence server). Observed behaviour is what gets logged.
     */
    expect: PromptNoneClass
}

/**
 * THE FULL MATRIX — distinct codebases → live endpoints. Tests iterate this and are
 * tolerant of unreachable hosts (skip with a recorded reason; never fail the run).
 *
 * Reachability and behaviour were observed credential-free on 2026-06-12; see the
 * follow-up comment on PR #13 for the rendered table.
 */
export const MATRIX: MatrixEntry[] = [
    // --- CSS (Community Solid Server, oidc-provider based) ---
    {
        id: "css-solidcommunity.net",
        issuer: "https://solidcommunity.net",
        codebase: "CSS (Community Solid Server)",
        note: "x-powered-by: Community Solid Server",
        expect: "interaction-error",
    },
    {
        id: "css-solidweb.me",
        issuer: "https://solidweb.me",
        codebase: "CSS (Community Solid Server)",
        expect: "interaction-error",
    },
    {
        id: "css-local",
        // Filled in at runtime from CSS_LOCAL_ISSUER (a server spun up for a full-control
        // CSS data point). Skipped cleanly when the env var is absent.
        issuer: process.env.CSS_LOCAL_ISSUER ?? null,
        codebase: "CSS (Community Solid Server, local full-control)",
        note: "npx @solid/community-server, in-memory; set CSS_LOCAL_ISSUER to run",
        expect: "interaction-error",
    },
    {
        id: "css-use.id",
        issuer: null,
        codebase: "CSS (Community Solid Server)",
        note: "host did not resolve on 2026-06-12 (DNS NXDOMAIN) — unreachable",
        expect: "unverified",
    },

    // --- Pivot (CSS remix, solid-contrib/pivot — distinct codebase, CSS-derived) ---
    {
        id: "pivot-teamid.live",
        issuer: "https://teamid.live",
        codebase: "Pivot (solid-contrib/pivot, CSS remix)",
        note: "canonical Pivot instance; inherits the CSS x-powered-by header",
        expect: "interaction-error",
    },

    // --- ESS (Enterprise Solid Server, Inrupt) ---
    {
        id: "ess-login.inrupt.com",
        issuer: "https://login.inrupt.com",
        codebase: "ESS (Enterprise Solid Server, Inrupt)",
        expect: "interaction-error",
    },

    // --- NSS (node-solid-server, legacy WebID-OIDC). HIGH VALUE divergence. ---
    {
        id: "nss-solidweb.org",
        issuer: "https://solidweb.org",
        codebase: "NSS (node-solid-server)",
        note: "solid-server/6.0.0; ignores prompt=none → serves HTML login (no OIDC error); no PKCE/DPoP advertised",
        expect: "html-login",
    },
    {
        id: "nss-datapod.igrant.io",
        issuer: "https://datapod.igrant.io",
        codebase: "NSS (node-solid-server)",
        note: "solid-server/5.7.4; same HTML-login divergence; discovery omits 'webid' scope",
        expect: "html-login",
    },
    {
        id: "nss-inrupt.net",
        issuer: null,
        codebase: "NSS (node-solid-server)",
        note: "/.well-known/openid-configuration → 404 on 2026-06-12 (root 303→start.inrupt.com); no conformant discovery doc",
        expect: "unverified",
    },

    // --- Trinpod (Graphmetrix / TwinPod-Server). Divergence too. ---
    {
        id: "trinpod-trinpod.us",
        issuer: "https://trinpod.us",
        codebase: "Trinpod (Graphmetrix TwinPod-Server)",
        note: "TwinPod-Server/3.6.940; ignores prompt=none → HTML login (/gmxLogin); no offline_access scope; auth_method client_secret_basic only",
        expect: "html-login",
    },
    {
        id: "trinpod-trinpod.eu",
        issuer: "https://trinpod.eu",
        codebase: "Trinpod (Graphmetrix TwinPod-Server)",
        note: "EU instance of the same codebase",
        expect: "html-login",
    },

    // --- Manas (Rust, manomayam) ---
    {
        id: "manas",
        issuer: null,
        codebase: "Manas (Rust, manomayam)",
        note: "no reachable public OIDC endpoint found (docs/self-host only) — unverified",
        expect: "unverified",
    },

    // --- PHP Solid Server (pdsinterop) ---
    {
        id: "php-pdsinterop",
        issuer: null,
        codebase: "PHP Solid Server (pdsinterop)",
        note: "no public hosted instance found (self-host/dev only) — unverified",
        expect: "unverified",
    },

    // --- Our broker (already covered; kept) ---
    {
        id: "broker-idp.solid-test.jeswr.org",
        issuer: "https://idp.solid-test.jeswr.org",
        codebase: "solid-test broker (Keycloak-fronted)",
        expect: "interaction-error",
    },
]

export const CALLBACK_URI = "https://example.org/callback"

function b64url(buf: Buffer): string {
    return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
}

export function pkcePair() {
    const verifier = b64url(randomBytes(32))
    const challenge = b64url(createHash("sha256").update(verifier).digest())
    return { verifier, challenge }
}

/** Discovery metadata fields the provider keys its behaviour off. */
export interface DiscoveryFacts {
    issuer?: string
    token_endpoint_auth_methods_supported?: string[]
    code_challenge_methods_supported?: string[]
    scopes_supported?: string[]
    dpop_signing_alg_values_supported?: string[]
    grant_types_supported?: string[]
    prompt_values_supported?: string[]
    registration_endpoint?: string
    authorization_endpoint?: string
}

export async function discover(request: APIRequestContext, issuer: string): Promise<DiscoveryFacts> {
    const res = await request.get(`${issuer}/.well-known/openid-configuration`)
    return res.json()
}

/** Dynamic client registration for a public (token_endpoint_auth_method=none) client. */
export async function register(
    request: APIRequestContext,
    registrationEndpoint: string,
    grantTypes: string[] = ["authorization_code"],
) {
    const res = await request.post(registrationEndpoint, {
        data: {
            redirect_uris: [CALLBACK_URI],
            grant_types: grantTypes,
            response_types: ["code"],
            token_endpoint_auth_method: "none",
        },
    })
    return res.json()
}

export interface SilentResult {
    /** OIDC error returned on the callback redirect, if any. */
    error: string | null
    errorDescription: string | null
    /** Whether a code was silently issued (warm-session success). */
    code: boolean
    /** HTTP status of the (last hop of the) authorize request. */
    status: number
    /**
     * Observed behaviour class:
     *  - "interaction-error": redirected to callback with an OIDC error
     *  - "html-login": served an HTML login page instead of a callback redirect (no OIDC error)
     *  - "code": a code was issued silently (warm session)
     *  - "other": something else (e.g. invalid_request, opaque non-callback redirect)
     */
    kind: "interaction-error" | "html-login" | "code" | "other"
    /** Where the chain landed, for the record. */
    finalUrl?: string
    contentType?: string | null
}

/**
 * Issues an UNAUTHENTICATED `prompt=none` authorization request (mirroring exactly what
 * DPoPTokenProvider#authenticate sends as its silent first attempt: PKCE/S256, scope
 * `openid webid`, prompt=none) and classifies how the AS responds. Follows up to a few
 * internal redirect hops to reach either the callback (error/code) or a terminal HTML page.
 */
export async function silentAttempt(request: APIRequestContext, issuer: string): Promise<SilentResult> {
    const disco = await discover(request, issuer)
    const reg = await register(request, disco.registration_endpoint as string)
    if (!reg.client_id) {
        throw new Error(`registration failed for ${issuer}: ${JSON.stringify(reg).slice(0, 200)}`)
    }

    const { challenge } = pkcePair()
    const u = new URL(disco.authorization_endpoint as string)
    u.searchParams.set("client_id", reg.client_id)
    u.searchParams.set("redirect_uri", CALLBACK_URI)
    u.searchParams.set("response_type", "code")
    u.searchParams.set("scope", "openid webid")
    u.searchParams.set("prompt", "none")
    u.searchParams.set("state", "s123")
    u.searchParams.set("nonce", "n123")
    u.searchParams.set("code_challenge_method", "S256")
    u.searchParams.set("code_challenge", challenge)

    let target = u.href
    let status = 0
    let contentType: string | null = null
    // Follow up to 5 internal interaction redirects to reach a terminal state.
    for (let hop = 0; hop < 6; hop++) {
        const res = await request.get(target, { maxRedirects: 0 })
        status = res.status()
        contentType = res.headers()["content-type"] ?? null
        const loc = res.headers()["location"]
        if (!loc) {
            // Terminal, non-redirect response. If it's an HTML page (not the callback),
            // the server ignored prompt=none and is showing an interactive login.
            const isHtml = (contentType ?? "").includes("text/html")
            return {
                error: null,
                errorDescription: null,
                code: false,
                status,
                kind: isHtml ? "html-login" : "other",
                finalUrl: target,
                contentType,
            }
        }
        const next = new URL(loc, issuer).href
        if (next.startsWith(CALLBACK_URI)) {
            const p = new URL(next).searchParams
            const code = p.get("code") !== null
            const error = p.get("error")
            return {
                error,
                errorDescription: p.get("error_description"),
                code,
                status,
                kind: code ? "code" : error ? "interaction-error" : "other",
                finalUrl: next,
                contentType,
            }
        }
        target = next
    }
    return { error: null, errorDescription: null, code: false, status, kind: "other", finalUrl: target, contentType }
}

/**
 * The three OIDC "the user must interact" errors that AuthorizationCodeFlow#needsInteraction
 * and DPoPTokenProvider#authenticate retry interactively. Kept in sync with the code under
 * test so the assertion is meaningful.
 */
export const INTERACTION_ERRORS = ["login_required", "interaction_required", "consent_required"] as const
