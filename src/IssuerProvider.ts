export interface IssuerProvider {
    getIssuer(request: Request): Promise<URL>
}
