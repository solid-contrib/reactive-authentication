import type { DatasetCore, Quad, Term } from "@rdfjs/types"

// TODO: Eliminate once N3 stops trying to nodejs the browser
export class SimpleDataset implements DatasetCore {
    readonly #quads: Quad[]

    constructor(quads: Quad[]) {
        this.#quads = quads
    }

    get size() {
        return this.#quads.length
    }

    add(quad: Quad) {
        if (!this.has(quad)) {
            this.#quads.push(quad)
        }

        return this
    }

    delete(quad: Quad) {
        const index = this.#quads.findIndex(q => q.equals(quad))
        if (index >= 0) {
            this.#quads.splice(index, 1)
        }

        return this
    }

    has(quad: Quad) {
        return this.#quads.some(q => q.equals(quad))
    }

    match(subject?: Term | null, predicate?: Term | null, object?: Term | null, graph?: Term | null) {
        return new SimpleDataset(this.#quads.filter(q =>
            (!subject || q.subject.equals(subject)) &&
            (!predicate || q.predicate.equals(predicate)) &&
            (!object || q.object.equals(object)) &&
            (!graph || q.graph.equals(graph))))
    }

    [Symbol.iterator]() {
        return this.#quads[Symbol.iterator]()
    }
}
