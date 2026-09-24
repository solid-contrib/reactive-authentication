/**
 * Storage for resolved values. Undefined means a miss and must not be stored.
 * Mutations resolve only after the storage operation completes; failures reject.
 * Each instance/namespace must belong to one component and authentication context.
 */
export interface Cache<T> {
    get(key: string): Promise<T | undefined>
    set(key: string, value: T): Promise<void>
    delete(key: string): Promise<void>
    clear(): Promise<void>
}
