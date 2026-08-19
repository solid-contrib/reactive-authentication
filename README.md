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

### Patch global `fetch`

The `ReactiveFetchManager` can monkey-patch global `fetch` to achieve the same effect:

```js
manager.registerGlobally()
const response = await fetch(requestUri)
```

### Pin the providers' own OIDC requests to a pristine `fetch`

The token providers perform their own network requests (discovery, dynamic client registration, the token grant) which default to `globalThis.fetch`. If the application patches the global `fetch` with an authenticating wrapper — `registerGlobally()`, or its own wrapper that single-flights concurrent requests onto one shared authentication attempt — those OIDC requests re-enter the wrapper mid-login. A single-flighting wrapper then awaits the very authentication attempt its request is serving: a circular await that hangs login before the authorization popup/redirect ever opens.

To avoid this, capture the pristine `fetch` before patching and pin the providers to it:

```js
const pristineFetch = globalThis.fetch.bind(globalThis) // capture BEFORE patching

const provider = new DPoPTokenProvider(callbackUri, getCode, getIssuer, {fetch: pristineFetch})
const manager = new ReactiveFetchManager([provider])
manager.registerGlobally()
```

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


## History

The paradigm employed here originates in [@langsamu](https://github.com/langsamu)'s research project [Solid Explorer](https://github.com/langsamu/solid-explorer/).

It was later expanded into a robust architecture by [@hellikopter](https://github.com/hellikopter) and [@langsamu](https://github.com/langsamu) in [.NET ReactiveAuthentication](https://github.com/ReactiveAuthentication/ReactiveAuthentication).
