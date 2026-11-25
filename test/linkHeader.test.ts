import assert from "node:assert/strict"
import {describe, it} from "node:test"
import {findLinkTarget} from "../src/linkHeader.js"

const storage = "http://www.w3.org/ns/lws#storage"

function respond(link: string | undefined, url = ""): Response {
    const response = new Response(null, link === undefined ? {} : {headers: {Link: link}})
    Object.defineProperty(response, "url", {value: url})
    return response
}

describe("findLinkTarget", () => {
    it("finds the LWS storage link", () => {
        assert.equal(findLinkTarget(respond(`<https://example.com/storage/>; rel="${storage}"`), storage), "https://example.com/storage/")
    })

    it("resolves a relative target against the response URL", () => {
        assert.equal(findLinkTarget(respond(`</storage/>; rel="${storage}"`, "https://example.com/a/b"), storage), "https://example.com/storage/")
    })

    it("skips a relative target without a response URL", () => {
        assert.equal(findLinkTarget(respond(`</storage/>; rel="${storage}", <https://example.com/s/>; rel="${storage}"`), storage), "https://example.com/s/")
    })

    it("picks the matching link among several", () => {
        assert.equal(findLinkTarget(respond(`<https://example.com/a>; rel="next", <https://example.com/b>; rel="${storage}"`), storage), "https://example.com/b")
    })

    it("finds a relation type among several in one link", () => {
        assert.equal(findLinkTarget(respond(`<https://example.com/a>; rel="next ${storage}"`), storage), "https://example.com/a")
    })

    it("returns the first of several matching links", () => {
        assert.equal(findLinkTarget(respond(`<https://example.com/a>; rel="${storage}", <https://example.com/b>; rel="${storage}"`), storage), "https://example.com/a")
    })

    it("compares registered relation types case-insensitively", () => {
        assert.equal(findLinkTarget(respond(`<https://example.com/a>; rel="NEXT"`), "next"), "https://example.com/a")
    })

    it("compares URI relation types exactly", () => {
        assert.equal(findLinkTarget(respond(`<https://example.com/a>; rel="${storage.toUpperCase()}"`), storage), undefined)
    })

    it("returns undefined without a Link header", () => {
        assert.equal(findLinkTarget(respond(undefined), storage), undefined)
    })

    it("returns undefined when no link has the relation type", () => {
        assert.equal(findLinkTarget(respond(`<https://example.com/a>; rel="next"`), storage), undefined)
    })

    it("returns undefined for a malformed header without throwing", () => {
        assert.equal(findLinkTarget(respond("https://example.com/a; rel=next"), storage), undefined)
        assert.equal(findLinkTarget(respond("<https://example.com/a"), storage), undefined)
    })
})
