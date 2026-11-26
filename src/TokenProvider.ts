export interface TokenProvider {
    matches(request: Request, response: Response): Promise<boolean>

    upgrade(request: Request, response: Response): Promise<Request>
}
