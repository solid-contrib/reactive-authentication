import type { WWWAuthenticateChallenge } from "oauth4webapi"

export interface TokenProvider {
    matches(request: Request, challenges: readonly WWWAuthenticateChallenge[]): Promise<boolean>

    upgrade(request: Request): Promise<Request>
}
