# Reactive authentication

[![Test Workflow](https://github.com/solid-contrib/reactive-authentication/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/solid-contrib/reactive-authentication/actions/workflows/ci.yml?query=branch%3Amain)
[![npm](https://img.shields.io/npm/v/@solid/reactive-authentication)](https://www.npmjs.com/package/@solid/reactive-authentication)

A reactive authentication library supporting Solid OIDC.

## Use

### Preliminaries

```ts
// The address of the protected resource to be requested
let requestUri: string

// The address of a page that users return to after Authoentication Code flow
let callbackUri: string

// A function that initiates Authorization Code flow and returns an Authorization Code
let getCode: (authorizationUri: URL, signal: AbortSignal) => Promise<string>

// A function that provides an Authorization Server URI based on the original request
let getIssuer: (request: Request) => Promise<URL>
```

### Wiring up UI

`getCode` and `getIssuer` above can implemented arbitrarily.

But they can also be hooked up to UI elements provided by this library.

If the DOM contains
```html
<authorization-code-flow></authorization-code-flow>
<idp-picker></idp-picker>
```

then the elements provide the required lambdas:

```js
const codeUi = document.querySelector("authorization-code-flow")
const issuerUi = document.querySelector("idp-picker")

getCode = codeUi.getCode.bind(codeUi)
getIssuer = issuerUi.getIssuer.bind(issuerUi)
```

### Setup

```js
import { DPoPTokenProvider, ReactiveFetchManager } from "@solid/reactive-authentication"

const provider = new DPoPTokenProvider(callbackUri, getCode, getIssuer)
const manager = new ReactiveFetchManager([provider])
```

### Use an authenticated `fetch`

The `ReactiveFetchManager` provides a `fetch` function that can be used to request protected resources:

```js
const response = await manager.fetch(requestUri)
```

### DPoP key algorithm

The DPoP key is non-extractable and its algorithm comes from the Authorization Server's `dpop_signing_alg_values_supported` metadata.

The first supported algorithm in the order ES256, EdDSA, PS256, RS256 is used. If the metadata is absent, ES256 is used. If the server supports none of them, an error is thrown.

### Provider matching

When a response has status `401`, the manager gives the request and the response to `matches` of each provider, in the order of the list.
The first provider that matches upgrades the request. It gets the same request and response in `upgrade`. A provider that needs the challenges parses the `WWW-Authenticate` header of the response.

| Provider                         | Matches when a challenge has scheme |
|----------------------------------|-------------------------------------|
| `DPoPTokenProvider`              | `DPoP` or `Bearer`                  |
| `ClientCredentialsTokenProvider` | `DPoP` or `Bearer`                  |
| `BearerTokenProvider`            | `Bearer`                            |
| `TokenExchangeTokenProvider`     | `DPoP` or `Bearer`, with `resource_metadata`, or with `as_uri` and `realm` (with `LwsTokenExchangeTargetProvider`) |

No provider matches when the header is missing, cannot be parsed or is not exposed to the browser by CORS.
Several providers can match the same response, so put the more specific provider earlier in the list.

### Caches

`CachingIssuerProvider`, `CachingAuthorizationServerProvider`, `CachingClientProvider` and `DPoPTokenProvider` keep what they learn in a `Cache`.
Each one takes a cache as its last constructor argument (for `DPoPTokenProvider` it comes after `options`, which can be `undefined`). Without one, each instance uses its own `MemoryCache`, as before.
`CachingIssuerProvider` stores entries under the key its `CacheKeyProvider` gives. The other three store entries under the issuer URL.

```ts
interface Cache<T> {
    getItem(key: string): Promise<T | null>
    setItem(key: string, value: T): Promise<void>
    removeItem(key: string): Promise<void>
}
```

The interface has the same shape as `KeyValueStore` in [Key Value Kit](https://github.com/jeswr/KeyValueKit), which has ready-made stores for browsers (memory, Web Storage, IndexedDB), Node.js, Bun, Deno, VS Code and Electron:

```js
import {createIndexedDbStore} from "@key-value-kit/storage/indexeddb"

const clientProvider = new CachingClientProvider(new DynamicRegistrationClientProvider, createIndexedDbStore({namespace: "my-app:clients:v1"}))
```

Points to watch:

- Cached values are the library's own objects. Use a store that keeps them as they are (memory, IndexedDB) or wrap a string store with a codec (Key Value Kit's `withCodec`). The issuer cache holds `URL` objects, which IndexedDB cannot store, so it needs a codec.
- The `DPoPTokenProvider` cache holds access tokens, refresh tokens and non-extractable DPoP key pairs. Never share it between clients or users, and never put it in `localStorage` or `sessionStorage`.
- A cache does not coordinate between tabs. `DPoPTokenProvider` uses a Web Lock so a refresh token is not used twice.

### Linked Web Storage (LWS)

`TokenExchangeTokenProvider` authenticates to storages that follow [LWS10-OAUTH](https://w3c.github.io/lws-protocol/lws10-oauth/). The flow is:

1. The storage answers a request with `401` and a challenge that has a `resource_metadata` parameter.
2. `LwsTokenExchangeTargetProvider` fetches the protected resource metadata. It checks the metadata, the storage `Link` header and the storage description, and finds the issuer of the authorization server and the resource.
3. `LwsDiscoveryAuthorizationServerProvider` fetches the authorization server metadata from `/.well-known/lws-configuration`.
4. `TokenExchangeTokenProvider` exchanges a subject token for an access token ([RFC 8693](https://www.rfc-editor.org/rfc/rfc8693.html)). `IdTokenSubjectTokenProvider` provides an ID token as the subject token, with the Authorization Code flow.
5. The access token is presented as `Bearer`, or as `DPoP` when the authorization server returns a `DPoP` token.

A challenge with `as_uri` and `realm` and no `resource_metadata` (the legacy challenge) also matches. Then `as_uri` is the issuer and `realm` is the resource.

Some servers, for example Inrupt ESS, have no `/.well-known/lws-configuration` and answer `404`. `FallbackAuthorizationServerProvider` then uses the metadata of RFC 8414 (`DiscoveryAuthorizationServerProvider` with `"oauth2"`).

```js
import {
    CachingAuthorizationServerProvider,
    CachingStorageRootProvider,
    DiscoveryAuthorizationServerProvider,
    FallbackAuthorizationServerProvider,
    IdTokenSubjectTokenProvider,
    LwsDiscoveryAuthorizationServerProvider,
    LwsStorageRootProvider,
    LwsTokenExchangeTargetProvider,
    ReactiveFetchManager,
    TokenExchangeTokenProvider
} from "@solid/reactive-authentication"

const asProvider = new CachingAuthorizationServerProvider(new FallbackAuthorizationServerProvider(new LwsDiscoveryAuthorizationServerProvider(), new DiscoveryAuthorizationServerProvider(undefined, "oauth2")))
const idTokens = new IdTokenSubjectTokenProvider(callbackUri, codeProvider, issuerProvider, opProvider, clientProvider)
const lws = new TokenExchangeTokenProvider(new LwsTokenExchangeTargetProvider(new CachingStorageRootProvider(new LwsStorageRootProvider())), idTokens, asProvider)
const manager = new ReactiveFetchManager([lws, dpopTokenProvider])
```

`opProvider` discovers the metadata of the OpenID Provider that issues the ID token (for example `DiscoveryAuthorizationServerProvider` with its default OIDC discovery). It is not the same instance as `asProvider`, which discovers the authorization server that does the token exchange.

`TokenExchangeTokenProvider` must come before `DPoPTokenProvider` in the list, because `DPoPTokenProvider` matches any `Bearer` challenge, also an LWS challenge.

The LWS code uses the runtime dependency `http-link-header`. In a browser without a bundler, add it to the import map, for example `"http-link-header": "https://esm.sh/http-link-header@1.1.4"`.

## Run the demo

To compile,
```batch
npm install
npm run build
```

Then, for the demo, run a web server on the root folder, e.g.
```batch
npx http-server
```

then navigate to [localhost:8080](http://localhost:8080) (or wherever it was served).

## Requirements

### Node.js

When using this library in Node.js, the minimum supported version is 24.5.

## History

The paradigm employed here originates in [@langsamu](https://github.com/langsamu)'s research project [Solid Explorer](https://github.com/langsamu/solid-explorer/).

It was later expanded into a robust architecture by [@hellikopter](https://github.com/hellikopter) and [@langsamu](https://github.com/langsamu) in [.NET ReactiveAuthentication](https://github.com/ReactiveAuthentication/ReactiveAuthentication).
