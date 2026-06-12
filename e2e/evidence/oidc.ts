import { createHash, randomBytes } from "node:crypto"
import type { APIRequestContext } from "@playwright/test"

/** The Solid authorization servers exercised as evidence. */
export const SERVERS = {
    /** Community Solid Server instance (oidc-provider based). */
    css: "https://solidcommunity.net",
    /** Enterprise Solid Server (Inrupt PodSpaces). */
    ess: "https://login.inrupt.com",
    /** The solid-test broker (Keycloak-fronted oidc-provider style broker). */
    broker: "https://idp.solid-test.jeswr.org",
} as const

export const CALLBACK_URI = "https://example.org/callback"

function b64url(buf: Buffer): string {
    return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
}

export function pkcePair() {
    const verifier = b64url(randomBytes(32))
    const challenge = b64url(createHash("sha256").update(verifier).digest())
    return { verifier, challenge }
}

export async function discover(request: APIRequestContext, issuer: string) {
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

/**
 * Issues an UNAUTHENTICATED `prompt=none` authorization request (mirroring exactly
 * what DPoPTokenProvider#authenticate sends as its silent first attempt: PKCE/S256,
 * scope `openid webid`, prompt=none) and returns the `error` the AS hands back on the
 * redirect to the callback — following one internal redirect hop if the AS bounces
 * through its own interaction UI first.
 */
export async function silentAttempt(
    request: APIRequestContext,
    issuer: string,
): Promise<{ error: string | null; errorDescription: string | null; code: boolean; status: number }> {
    const disco = await discover(request, issuer)
    const reg = await register(request, disco.registration_endpoint)
    if (!reg.client_id) {
        throw new Error(`registration failed for ${issuer}`)
    }

    const { challenge } = pkcePair()
    const u = new URL(disco.authorization_endpoint)
    u.searchParams.set("client_id", reg.client_id)
    u.searchParams.set("redirect_uri", CALLBACK_URI)
    u.searchParams.set("response_type", "code")
    u.searchParams.set("scope", "openid webid")
    u.searchParams.set("prompt", "none")
    u.searchParams.set("state", "s123")
    u.searchParams.set("nonce", "n123")
    u.searchParams.set("code_challenge_method", "S256")
    u.searchParams.set("code_challenge", challenge)

    let res = await request.get(u.href, { maxRedirects: 0 })
    let status = res.status()
    let loc = res.headers()["location"]
    let target = loc ? new URL(loc, issuer).href : ""

    // Follow one internal interaction redirect (AS-side UI) to reach the callback.
    if (target && !target.startsWith(CALLBACK_URI)) {
        res = await request.get(target, { maxRedirects: 0 })
        status = res.status()
        loc = res.headers()["location"]
        target = loc ? new URL(loc, issuer).href : ""
    }

    if (target.startsWith(CALLBACK_URI)) {
        const p = new URL(target).searchParams
        return {
            error: p.get("error"),
            errorDescription: p.get("error_description"),
            code: p.get("code") !== null,
            status,
        }
    }

    return { error: null, errorDescription: null, code: false, status }
}

/**
 * The three OIDC "the user must interact" errors that AuthorizationCodeFlow#needsInteraction
 * and DPoPTokenProvider#authenticate retry interactively. Kept in sync with the code under
 * test so the assertion is meaningful.
 */
export const INTERACTION_ERRORS = ["login_required", "interaction_required", "consent_required"] as const
