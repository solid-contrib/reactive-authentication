/**
 * Internal async key-value storage, shaped after KeyValueKit's `KeyValueStore`.
 * `null` means a miss, so `null` and `undefined` cannot be stored.
 */
export interface Cache<T extends NonNullable<unknown>> {
    getItem(key: string): Promise<T | null>
    setItem(key: string, value: T): Promise<void>
    removeItem(key: string): Promise<void>
}
