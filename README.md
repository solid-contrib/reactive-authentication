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

### Caches

`CachingIssuerProvider`, `CachingAuthorizationServerProvider`, `CachingClientProvider` and `DPoPTokenProvider` keep what they learn in a `Cache`.
Each one takes a cache as its last constructor argument. Without one, each instance uses its own `MemoryCache`, as before.

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
