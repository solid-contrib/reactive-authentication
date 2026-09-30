export interface Cache<T extends NonNullable<unknown>> {
    getItem(key: string): Promise<T | null>
    setItem(key: string, value: T): Promise<void>
    removeItem(key: string): Promise<void>
}
