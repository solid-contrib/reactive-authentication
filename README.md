# Reactive authentication

[![Test Workflow](https://github.com/solid-contrib/reactive-authentication/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/solid-contrib/reactive-authentication/actions/workflows/ci.yml?query=branch%3Amain)
[![npm](https://img.shields.io/npm/v/@solid/reactive-authentication)](https://www.npmjs.com/package/@solid/reactive-authentication)

A reactive authentication library supporting Solid OIDC.

## Use

### Preliminaries

```ts
// The address of the protected resource to be requested
let requestUri: string

// The address of a page that users return to after Authorization Code flow
let callbackUri: string

// A function that provides an Authorization Server URI based on the original request
let getIssuer: (request: Request) => Promise<URL>
```

### Wiring up UI

The `CodeProvider` interface and `getIssuer` above can be implemented arbitrarily.

But they can also be hooked up to UI elements provided by this library.

If the DOM contains
```html
<authorization-code-flow></authorization-code-flow>
<idp-picker></idp-picker>
```

then the elements provide the code provider and issuer callback:

```js
const codeUi = document.querySelector("authorization-code-flow")
const issuerUi = document.querySelector("idp-picker")

getIssuer = issuerUi.getIssuer.bind(issuerUi)
```

### Setup

```js
import {
    DPoPTokenProvider, ReactiveFetchManager, CachingIssuerProvider,
    XASProvider, CachingAuthorizationServerProvider,
    DynamicRegistrationClientProvider, CachingClientProvider,
} from "@solid/reactive-authentication"

// codeUi implements CodeProvider (including disposal of the popup).
const issuer = new CachingIssuerProvider({ getIssuer })
const authorizationServer = new CachingAuthorizationServerProvider(new XASProvider(issuer))
const client = new CachingClientProvider(new DynamicRegistrationClientProvider())
const provider = new DPoPTokenProvider(callbackUri, codeUi, authorizationServer, client)
const manager = new ReactiveFetchManager([provider])
```

### Use an authenticated `fetch`

The `ReactiveFetchManager` provides a `fetch` function that can be used to request protected resources:

```js
const response = await manager.fetch(requestUri)
```

### Configurable caches

All existing caching providers accept an optional final `Cache<T>` argument. Omitting it creates a separate `MemoryCache` for each provider. `Cache<T>` has asynchronous `get`, `set`, `delete`, and `clear` methods; `get` returns `undefined` on a miss. Store resolved values, never promises or `undefined`. Mutations must finish before their promises resolve, and storage errors must reject.

| Component | Cache value | Current key |
| --- | --- | --- |
| `CachingIssuerProvider` | `string` (issuer URL serialized as `href`) | Request URL |
| `CachingAuthorizationServerProvider` | `oauth.AuthorizationServer` | Request URL |
| `CachingClientProvider` | `oauth.Client` (may include secrets) | Issuer |
| `DPoPTokenProvider` | `DPoPTokenCacheEntry` (tokens, key pair, client, server, creation time) | Request URL |

Issuer values are strings because `URL` is not a portable structured-clone storage type; callers still receive a `URL`. Request-to-storage resolution is separate future work in [#46](https://github.com/solid-contrib/reactive-authentication/issues/46). Sharing a cache across clients or accounts can authenticate as the wrong user: use a distinct cache namespace for each application, client configuration (including redirect URI), and account. A namespace is isolation by convention, not a security boundary against same-origin scripts.

#### Browser preset

`createBrowserCaches` explicitly opts into IndexedDB for issuer choices and discovery metadata with a one-hour write-time TTL. This is an application cache policy, not HTTP cache revalidation. Client registrations and credentials remain in memory. The lifetime is configurable in milliseconds:

```js
import { createBrowserCaches } from "@solid/reactive-authentication"

// Use an application-owned context identifier; never put tokens in namespaces.
const caches = createBrowserCaches("my-app/client-config-1/account-1", 60 * 60 * 1000)
const issuer = new CachingIssuerProvider({ getIssuer }, caches.issuer)
const authorizationServer = new CachingAuthorizationServerProvider(new XASProvider(issuer), caches.authorizationServer)
const client = new CachingClientProvider(new DynamicRegistrationClientProvider(), caches.client)
const provider = new DPoPTokenProvider(callbackUri, codeUi, authorizationServer, client, caches.token)
```

Choose storage according to the data:

| Data | Recommended default | Optional persistence |
| --- | --- | --- |
| Issuer choices and public discovery metadata | Expiring IndexedDB | Web Storage with an explicit codec; memory for private browsing requirements |
| Client registrations, access tokens, refresh tokens | Memory | Explicit IndexedDB opt-in with application-managed lifetime and account isolation |
| DPoP private keys | Non-extractable Web Crypto keys in memory | IndexedDB structured clone, together with their bound tokens |
| DPoP proofs, authorization codes, PKCE verifiers, OAuth state/nonce | Per-request/flow only | Do not cache |

The [IndexedDB API](https://www.w3.org/TR/IndexedDB/) stores structured-cloneable objects, including [Web Crypto keys](https://www.w3.org/TR/webcrypto-2/). The [Credential Management API](https://www.w3.org/TR/credential-management-1/) does not provide a generic OAuth token store. `localStorage` and `sessionStorage` store strings, cannot preserve a non-extractable key, and are accessible to same-origin scripts; `sessionStorage` is also unavailable in workers. Cache Storage is designed for HTTP request/response pairs rather than these typed credential records.

#### Explicit credential persistence

```ts
import { IndexedDbCache, type DPoPTokenCacheEntry } from "@solid/reactive-authentication"

const tokens = new IndexedDbCache<DPoPTokenCacheEntry>("my-app/client-config-1/account-1/tokens-v1")
const provider = new DPoPTokenProvider(callbackUri, codeUi, authorizationServer, client, tokens)
```

This persists the **whole credential record**, including access/refresh tokens and any client secret, atomically with its non-extractable key pair. It is not a refresh-only session store. On reload an unexpired access token is reused; expired tokens follow the existing refresh flow. A new DPoP proof is signed for every request. Do not use JSON serialization or export private keys to persist this record. Persisted token responses also do not retain oauth4webapi's in-memory validation associations; they are not a substitute for revalidating identity claims.

Token reads, refreshes, and committed writes remain inside the existing request-URL Web Lock. Before a refresh grant, the old record is removed so a crash or failed replacement write cannot leave a consumed rotating refresh token for another tab to retry. A failed grant/write may therefore require authorization again. Only share this storage among cooperating providers in the same browser storage/lock partition; it is not a distributed refresh lock for server processes.

Non-extractable keys prevent private-key export, but malicious same-origin JavaScript can still use a stored key to sign requests. Persistence increases exposure and does not promise hardware-backed storage or encryption at rest; see [OAuth 2.0 for Browser-Based Applications](https://www.rfc-editor.org/rfc/rfc10017.html). An application's consent, retention and logout policy must account for that.

#### Other adapters and cache management

`WebStorageCache` accepts a `Storage`, namespace, and codec. The codec must encode, decode, and validate its value type; use this only for non-secret data. For example, an issuer cache with tab-session lifetime:

```ts
import { WebStorageCache } from "@solid/reactive-authentication"

const issuerCache = new WebStorageCache<string>(sessionStorage, "my-app/account-1/issuers-v1", {
    encode: value => new URL(value).href,
    decode: value => new URL(value).href,
})
const issuer = new CachingIssuerProvider({ getIssuer }, issuerCache)
```

`ExpiringCache<T>` wraps a `Cache<ExpiringCacheEntry<T>>` with an absolute TTL. Expired entries are misses; reads never extend their lifetime or delete a concurrently replaced value. Expired records remain stored until overwritten, explicitly deleted, or cleared. Do not use access-token expiry as the TTL for the entire credential record: its refresh token may still be usable.

Retain cache references to `delete(key)` or `clear()` them. Persistent adapters clear only their own namespace. Before clearing authentication state, stop and await in-flight upgrades and coordinate other tabs; clearing is not a cancellation fence, token revocation, or IdP logout. On account changes, also invalidate the issuer selection and client configuration as appropriate. Full logout semantics are tracked separately in #23.

Storage can be denied, evicted, or run out of quota. Empty/evicted storage yields a miss; blocked database opens, failed transactions, codec errors, and quota/security errors reject. There is no silent memory fallback, which could split rotating-token state between tabs. Applications that cannot use persistence can select `MemoryCache` explicitly. Cache modules do not read browser globals at import time; browser APIs are accessed only when constructing/using their adapters. Use versioned namespaces when changing persisted value schemas and validate data in custom adapters where required.

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

## Testing

Run `npm test` for the TypeScript build and Node test suite. IndexedDB unit tests use the dev-only `fake-indexeddb` implementation. For a real-browser smoke test, build, serve the repository over localhost, and open `test/browser-cache.html`. It reloads itself and checks persisted non-extractable key signing, both Web Storage APIs, the browser preset, and namespace isolation; the page reports `PASS` or `FAIL`.

## Requirements

### Node.js

When using this library in Node.js, the minimum supported version is 24.5.

## History

The paradigm employed here originates in [@langsamu](https://github.com/langsamu)'s research project [Solid Explorer](https://github.com/langsamu/solid-explorer/).

It was later expanded into a robust architecture by [@hellikopter](https://github.com/hellikopter) and [@langsamu](https://github.com/langsamu) in [.NET ReactiveAuthentication](https://github.com/ReactiveAuthentication/ReactiveAuthentication).
