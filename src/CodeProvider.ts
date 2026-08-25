export interface CodeProvider {
    getCode(authorizationUri: URL, signal: AbortSignal): Promise<string>

    cleanup(): void
}
