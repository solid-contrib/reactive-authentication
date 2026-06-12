// @vitest-environment happy-dom
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { AuthorizationCodeFlow } from "../src/AuthorizationCodeFlow.js"

customElements.define("authorization-code-flow", AuthorizationCodeFlow)

const authorizationUrl = new URL("https://as.test/authorize?prompt=none&state=s1")

/** The popup window handed out by the stubbed `open()`. */
interface FakePopup {
    close: ReturnType<typeof vi.fn>
    focus: ReturnType<typeof vi.fn>
    closed: boolean
}

let element: AuthorizationCodeFlow
let popup: FakePopup
let openWindow: ReturnType<typeof vi.fn>

beforeEach(() => {
    popup = {close: vi.fn(), focus: vi.fn(), closed: false}
    openWindow = vi.fn(() => popup as unknown as WindowProxy)
    vi.stubGlobal("open", openWindow)

    element = document.createElement("authorization-code-flow") as AuthorizationCodeFlow
    document.body.appendChild(element)
})

afterEach(() => {
    element.remove()
    vi.unstubAllGlobals()
})

/** Starts a flow and waits until the authorization popup has been opened. (Wrapped in an object so the async function does not flatten the pending flow promise.) */
async function startFlow(url = authorizationUrl): Promise<{flow: Promise<string>}> {
    const flow = element.getCode(url, new AbortController().signal)
    await vi.waitFor(() => expect(openWindow).toHaveBeenCalled())
    return {flow}
}

/** Delivers an authorization response the way callback.html does: a message on the hosting window. */
function postMessage(data: unknown, source: unknown = popup): void {
    window.dispatchEvent(new MessageEvent("message", {data, source: source as Window}))
}

describe("AuthorizationCodeFlow popup reuse on the interactive retry", () => {
    // regression: PR #13 (fix/popup-retry-window-reuse) — f1d7c1a: the popup must stay
    // open when the silent (prompt=none) attempt bounces with a "user must interact"
    // error, so the retry's open() NAVIGATES the existing named window. Closing it
    // would force the retry to create a NEW window outside the original click's
    // (already consumed) user activation — popup blockers stop that, stranding the
    // user in the "Open new window" dialog on every first login.
    it("keeps the popup open on login_required so the interactive retry reuses the window", async () => {
        const {flow} = await startFlow()

        postMessage("https://app.test/callback.html?error=login_required&state=s1")

        await expect(flow).resolves.toContain("error=login_required")
        expect(popup.close).not.toHaveBeenCalled()

        // The interactive retry targets the same named window: navigation, not a second popup.
        const retry = element.getCode(new URL("https://as.test/authorize?prompt=consent&state=s2"), new AbortController().signal)
        await vi.waitFor(() => expect(openWindow).toHaveBeenCalledTimes(2))
        expect(openWindow.mock.calls[1]?.[1]).toBe(openWindow.mock.calls[0]?.[1])
        expect(popup.close).not.toHaveBeenCalled()

        postMessage("https://app.test/callback.html?code=abc&state=s2")

        await expect(retry).resolves.toContain("code=abc")
        expect(popup.close).toHaveBeenCalledTimes(1) // a code is terminal: now the window closes
    })

    // regression: PR #13 (fix/popup-retry-window-reuse) — f1d7c1a: only the OIDC "user
    // must interact" errors keep the window; terminal errors close it as before.
    it("still closes the popup on a terminal error response", async () => {
        const {flow} = await startFlow()

        postMessage("https://app.test/callback.html?error=access_denied&state=s1")

        await expect(flow).resolves.toContain("error=access_denied")
        expect(popup.close).toHaveBeenCalledTimes(1)
    })
})

describe("AuthorizationCodeFlow message source filtering", () => {
    // regression: PR #13 (fix/popup-retry-window-reuse) — 1ce81c1: only the authorization
    // popup's messages may end the flow. Without the source check, any window (other
    // components, extensions, a hostile frame) could spoof an authorization response
    // or terminate the flow early.
    it("ignores messages whose source is not the authorization popup", async () => {
        const {flow} = await startFlow()
        const settled = vi.fn()
        void flow.then(settled, settled)

        const spoof = "https://app.test/callback.html?code=spoofed&state=s1"
        postMessage(spoof, {}) // a hostile frame
        postMessage(spoof, window) // the page itself
        postMessage(spoof, null) // no source at all

        await new Promise(resolve => setTimeout(resolve))
        expect(settled).not.toHaveBeenCalled()
        expect(popup.close).not.toHaveBeenCalled()

        // The genuine popup response still ends the flow: the listener survived the noise.
        postMessage("https://app.test/callback.html?code=genuine&state=s1")

        await expect(flow).resolves.toContain("code=genuine")
    })
})
