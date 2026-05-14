export interface TokenProvider {
    matches(request: Request): Promise<boolean>

    upgrade(request: Request): Promise<Request>
}
