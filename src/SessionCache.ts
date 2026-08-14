/**
 * Where a token provider keeps established sessions.
 *
 * @remarks Asynchronous so sessions can live wherever the host offers, such as
 * IndexedDB in a browser or the secrets API in an editor extension.
 */
export interface SessionCache<T> {
    get(key: string): Promise<T | undefined>

    set(key: string, value: T): Promise<void>

    delete(key: string): Promise<void>
}
