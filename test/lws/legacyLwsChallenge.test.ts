import assert from "node:assert/strict"
import {describe, it} from "node:test"
import {findLegacyLwsChallenge, isWithinRealm} from "../../src/lws/legacyLwsChallenge.js"
import {parseChallenges} from "../../src/parseChallenges.js"

describe("findLegacyLwsChallenge", () => {
    it("finds an ESS-style challenge with an origin realm", () => {
        const result = findLegacyLwsChallenge(parseChallenges('Bearer realm="https://storage.odi.ess.solid-experiments.org", as_uri="https://platform.odi.ess.solid-experiments.org"'))
        assert.equal(result?.realm, "https://storage.odi.ess.solid-experiments.org")
        assert.equal(result?.asUri, "https://platform.odi.ess.solid-experiments.org")
    })

    it("finds the specification example", () => {
        const result = findLegacyLwsChallenge(parseChallenges('Bearer as_uri="https://authorization.example", realm="https://storage.example/storage_1", error="invalid_token"'))
        assert.equal(result?.asUri, "https://authorization.example")
        assert.equal(result?.realm, "https://storage.example/storage_1")
    })

    it("returns undefined without as_uri", () => {
        assert.equal(findLegacyLwsChallenge(parseChallenges('Bearer realm="https://storage.example"')), undefined)
    })

    it("returns undefined without realm", () => {
        assert.equal(findLegacyLwsChallenge(parseChallenges('Bearer as_uri="https://as.example"')), undefined)
    })

    it("returns undefined for values that are not URLs", () => {
        assert.equal(findLegacyLwsChallenge(parseChallenges('Bearer realm="storage", as_uri="as"')), undefined)
    })

    it("skips an invalid challenge and finds a later valid one", () => {
        const result = findLegacyLwsChallenge(parseChallenges('Bearer realm="storage", as_uri="as", DPoP realm="https://storage.example", as_uri="https://as.example"'))
        assert.equal(result?.asUri, "https://as.example")
        assert.equal(result?.realm, "https://storage.example")
    })

    it("matches the scheme case-insensitively", () => {
        const result = findLegacyLwsChallenge(parseChallenges('DPoP realm="https://storage.example", as_uri="https://as.example"'))
        assert.equal(result?.asUri, "https://as.example")
    })

    it("ignores other schemes", () => {
        assert.equal(findLegacyLwsChallenge(parseChallenges('Basic realm="https://storage.example", as_uri="https://as.example"')), undefined)
    })

    it("returns undefined for no challenges", () => {
        assert.equal(findLegacyLwsChallenge([]), undefined)
    })
})

describe("isWithinRealm", () => {
    const within = (request: string, realm: string) => isWithinRealm(new URL(request), realm)

    it("contains everything on the origin for a root realm", () => {
        assert.equal(within("https://storage.example/a/b", "https://storage.example"), true)
        assert.equal(within("https://storage.example/", "https://storage.example/"), true)
    })

    it("contains the realm path and its descendants", () => {
        const realm = "https://storage.example/storage_1"
        assert.equal(within("https://storage.example/storage_1", realm), true)
        assert.equal(within("https://storage.example/storage_1/", realm), true)
        assert.equal(within("https://storage.example/storage_1/x", realm), true)
    })

    it("does not match across a segment boundary", () => {
        assert.equal(within("https://storage.example/storage_10", "https://storage.example/storage_1"), false)
    })

    it("handles a realm with a trailing slash", () => {
        const realm = "https://storage.example/storage_1/"
        assert.equal(within("https://storage.example/storage_1/x", realm), true)
        assert.equal(within("https://storage.example/storage_10", realm), false)
    })

    it("ignores query and fragment", () => {
        assert.equal(within("https://storage.example/storage_1/x?a=/b#/c", "https://storage.example/storage_1"), true)
        assert.equal(within("https://storage.example/other?/storage_1/x", "https://storage.example/storage_1"), false)
    })

    it("rejects another origin", () => {
        assert.equal(within("https://other.example/storage_1/x", "https://storage.example/storage_1"), false)
        assert.equal(within("http://storage.example/x", "https://storage.example"), false)
    })
})
