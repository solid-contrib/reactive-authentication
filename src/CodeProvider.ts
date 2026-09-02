export interface CodeProvider {
    // TODO: Document dispose cleaning up e.g. closing window
    getCode(authorizationUri: URL, signal: AbortSignal): Promise<Disposable & { get value(): string }>
}
