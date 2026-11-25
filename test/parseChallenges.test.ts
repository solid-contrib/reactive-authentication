import assert from "node:assert/strict"
import {describe, it} from "node:test"
import {parseChallenges} from "../src/parseChallenges.js"

describe("parseChallenges", () => {
    it("returns no challenges for a null header", () => {
        assert.deepEqual(parseChallenges(null), [])
    })

    it("returns no challenges for an empty header", () => {
        assert.deepEqual(parseChallenges(""), [])
    })

    it("parses an ESS-style Bearer challenge", () => {
        assert.deepEqual(
            parseChallenges('Bearer realm="https://storage.example", as_uri="https://platform.example"'),
            [{scheme: "bearer", parameters: {realm: "https://storage.example", as_uri: "https://platform.example"}}]
        )
    })

    it("parses multiple challenges", () => {
        assert.deepEqual(
            parseChallenges('Bearer realm="a", DPoP algs="ES256 PS256", error=invalid_token'),
            [
                {scheme: "bearer", parameters: {realm: "a"}},
                {scheme: "dpop", parameters: {algs: "ES256 PS256", error: "invalid_token"}}
            ]
        )
    })

    it("lowercases scheme and parameter names but not values", () => {
        assert.deepEqual(
            parseChallenges('BEARER Realm="Mixed", AS_URI="https://Platform.example"'),
            [{scheme: "bearer", parameters: {realm: "Mixed", as_uri: "https://Platform.example"}}]
        )
    })

    it("unescapes quoted values", () => {
        assert.deepEqual(
            parseChallenges('Bearer realm="say \\"hi\\", please"'),
            [{scheme: "bearer", parameters: {realm: 'say "hi", please'}}]
        )
    })

    it("parses a challenge without parameters", () => {
        assert.deepEqual(parseChallenges("Bearer"), [{scheme: "bearer", parameters: {}}])
    })

    it("parses a token68 challenge", () => {
        assert.deepEqual(
            parseChallenges("Negotiate abc123=="),
            [{scheme: "negotiate", parameters: {}, token68: "abc123=="}]
        )
    })

    it("returns no challenges for a malformed header", () => {
        assert.deepEqual(parseChallenges('Bearer realm="unterminated'), [])
    })
})
