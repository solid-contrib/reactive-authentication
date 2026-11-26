import assert from "node:assert/strict"
import {describe, it} from "node:test"
import type {AuthorizationServer} from "oauth4webapi"
import {ReactiveAuthenticationError} from "../src/ReactiveAuthenticationError.js"
import {selectDPoPSigningAlgorithm} from "../src/selectDPoPSigningAlgorithm.js"

const server = (algorithms?: string[]): AuthorizationServer =>
    algorithms === undefined
        ? {issuer: "https://issuer.example"}
        : {issuer: "https://issuer.example", dpop_signing_alg_values_supported: algorithms}

describe("selectDPoPSigningAlgorithm", () => {
    it("falls back to ES256 when the server advertises nothing", () => {
        assert.equal(selectDPoPSigningAlgorithm(server()), "ES256")
    })

    it("prefers ES256, EdDSA, PS256, RS256 in that order", () => {
        assert.equal(selectDPoPSigningAlgorithm(server(["RS256", "PS256", "EdDSA", "ES256"])), "ES256")
        assert.equal(selectDPoPSigningAlgorithm(server(["RS256", "PS256", "EdDSA"])), "EdDSA")
        assert.equal(selectDPoPSigningAlgorithm(server(["RS256", "PS256"])), "PS256")
        assert.equal(selectDPoPSigningAlgorithm(server(["RS256"])), "RS256")
    })

    it("ignores unsupported algorithms", () => {
        assert.equal(selectDPoPSigningAlgorithm(server(["ES384", "RS256"])), "RS256")
    })

    it("throws when none of the advertised algorithms is supported", () => {
        assert.throws(() => selectDPoPSigningAlgorithm(server(["ES384", "ES512"])), ReactiveAuthenticationError)
    })

    it("throws for an advertised empty list", () => {
        assert.throws(() => selectDPoPSigningAlgorithm(server([])), ReactiveAuthenticationError)
    })
})
