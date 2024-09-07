# webauthn keys
![tests](https://github.com/bicycle-codes/webauthn-keys/actions/workflows/nodejs.yml/badge.svg)
[![types](https://img.shields.io/npm/types/@bicycle-codes/webauthn-keys?style=flat-square)](README.md)
[![module](https://img.shields.io/badge/module-ESM-blue?style=flat-square)](README.md)
[![semantic versioning](https://img.shields.io/badge/semver-2.0.0-blue?logo=semver&style=flat-square)](https://semver.org/)
[![install size](https://packagephobia.com/badge?p=@bicycle-codes/webauthn-keys)](https://packagephobia.com/result?p=@bicycle-codes/webauthn-keys)
[![dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen.svg?style=flat-square)](package.json)
[![license](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat-square)](LICENSE)

A simple way to use crypto keys, protected by [webauthn](https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API) (biometric authentication).

Save an ECC keypair, then access it iff the user authenticates via `webauthn`.

[See a live demo](https://bicycle-codes.github.io/webauthn-keys/)

<!-- toc -->

- [install](#install)
- [how it works](#how-it-works)
- [Use](#use)
  * [ESM](#esm)
  * [pre-built JS](#pre-built-js)
- [example](#example)
- [API](#api)
  * [`create`](#create)
  * [`getKeys`](#getkeys)
  * [`signData`](#signdata)
  * [`encrypt`](#encrypt)
  * [`decrypt`](#decrypt)
  * [`localIdentities`](#localidentities)
- [develop](#develop)
  * [start a local server](#start-a-local-server)
- [test](#test)
  * [start tests & watch for file changes](#start-tests--watch-for-file-changes)
  * [run tests and exit](#run-tests-and-exit)
- [see also](#see-also)
  * [What's the WebAuthn User Handle (`response.userHandle`)?](#whats-the-webauthn-user-handle-responseuserhandle)
  * [`libsodium` docs](#libsodium-docs)
- [credits](#credits)

<!-- tocstop -->

## install

```sh
npm i -S @bicycle-codes/webauthn-keys
```

## how it works

We [save the `iv` of the our keypair](./src/index.ts#L80), which lets us [re-create the same keypair](https://libsodium.gitbook.io/doc/public-key_cryptography/public-key_signatures#key-pair-generation) on subsequent sessions.

The secret `iv` is set in the `user.id` property in a [PublicKeyCredentialCreationOptions](https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialCreationOptions) object. The browser saves the credential, and will only read it after successful authentication with the `webauthn` API.

> [!NOTE]  
> We are not using the [webcrypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) for creating keys, because we are waiting on ECC support in all browsers.

> [!NOTE]  
> [We only need 1 keypair](https://libsodium.gitbook.io/doc/quickstart#how-can-i-sign-and-encrypt-using-the-same-key-pair) for both signing and encrypting. Internally, we create 2 keypairs -- one for signing and one for encryption, but this is hidden from the interface.

## Use
This exposes ESM via [package.json `exports` field](https://nodejs.org/api/packages.html#exports).

### ESM
```js
import {
    create,
    getKeys,
    encrypt,
    decrypt,
    signData,
    verify,
    toBase64String,
    fromBase64String,
    localIdentities,
    storeLocalIdentities,
    pushLocalIdentity,
} from '@bicycle-codes/webauthn-keys'

// and types
import type {
    Identity,
    RegistrationResult,
    LockKey,
    JSONValue,
    AuthResult
} from '@bicycle-codes/webauthn-keys'
```

### pre-built JS
This package exposes minified JS files too. Copy them to a location that is
accessible to your web server, then link to them in HTML.

#### copy
```sh
cp ./node_modules/@bicycle-codes/package/dist/index.min.js ./public/webauthn-keys.min.js
```

#### HTML
```html
<script type="module" src="./webauthn-keys.min.js"></script>
```

## example
Create a new keypair, and protect it with the `webatuhn` API.

```ts
import { create } from '@bicycle-codes/webauthn-keys'

const id = await create({
    username: 'alice',  // unique within relying party (this device)
    displayName: 'Alice Example',  // human-readable name
    relyingPartyName: 'Example application'  // rp.name
})
```

### See also
* [username property](https://www.corbado.com/blog/webauthn-user-id-userhandle#webauthn-user-name)
* [displayName property](https://www.corbado.com/blog/webauthn-user-id-userhandle#webauthn-user-display-name)
* [What's the Difference Between User Name and User Display Name?](https://www.corbado.com/blog/webauthn-user-id-userhandle#user-name-vs-user-display-name)

## API

### `create`
Create a new keypair.

```ts
async function create (
    lockKey = deriveLockKey(),
    opts:Partial<{
        username:string
        displayName:string
        relyingPartyID:string
        relyingPartyName:string
    }> = {
        username: 'local-user',
        displayName: 'Local User',
        relyingPartyID: document.location.hostname,
        relyingPartyName: 'wacg'
    }
):Promise<{ localID:string, record:Identity, keys:LockKey }>
```

#### `create` example

```js
import {
    create,
    pushLocalIdentity
} from '@bicycle-codes/webauthn-keys'

const { record, keys, localID } = await create(undefined, {
    username: 'alice',
    displayName: 'Alice Example',
    relyingPartyID: location.hostname,
    relyingPartyName: 'Example application'
})

//
// Save the ID to indexedDB.
// This saves public info only, not keys.
//
await pushLocalIdentity(id.localID, id.record)
```

### `getKeys`
Authenticate with a saved identity; takes the local user ID, which you would need to get somehow.

```ts
async function getKeys (
    localID:string
):Promise<{ record:Identity, keys:LockKey }>
```

#### `getKeys` example

```ts
import { getKeys } from '@bicycle-codes/webauthn-keys'

// The local ID is a random string created when you call `create`
const localID = 'Chp8eTUpF9mSWKlDBCeb'

const { record, keys } = await getKeys(localID)
```

### `signData`
```ts
export async function signData (data:string|Uint8Array, key:LockKey, opts?:{
    outputFormat?:'base64'|'raw'
}):Promise<Uint8Array>
```

#### `signData` example
```ts
import { signData, deriveLockKey } from '@bicycle-codes/webauthn-keys'

// create a new keypair
const key = await deriveLockKey()

const sig = await signData('hello world', key)
// => INZ2A9Lt/zL6Uf6d6D6fNi95xSGYDiUpK3tr/zz5a9iYyG5u...
```

### `encrypt`

```ts
export function encrypt (
    data:JSONValue,
    lockKey:LockKey,
    opts:{
        outputFormat:'base64'|'raw';
    } = { outputFormat: 'base64' }
// return type depends on the given output format
):string|Uint8Array
```

#### `encrypt` example
```js
import { encrypt } from '@bicycle-codes/webauthn-keys'

const encrypted = encrypt('hello encryption', myKeys)
// => XcxWEwijaHq2u7aui6BBYGjIrjVTkLIS5...
```

### `decrypt`

```ts
function decrypt (
    data:string|Uint8Array,
    lockKey:LockKey,
    opts:{ outputFormat?:'utf8'|'raw', parseJSON?:boolean } = {
        outputFormat: 'utf8',
        parseJSON: true
    }
):string|Uint8Array|JSONValue
```

#### `decrypt` example

```js
import { decrypt } from '@bicycle-codes/webauthn-keys'

const decrypted = decrypt('XcxWEwijaHq2u7aui6B...', myKeys, {
    parseJSON: false
})

// => 'hello encryption'
```

### `localIdentities`
Load local identities from indexed DB, return a dictionary from user ID to the identity record.

```ts
async function localIdentities ():Promise<Record<string, Identity>>
```

#### `localIdentities` example

```js
import { localIdentites } from '@bicycle-codes/webauthn-keys'

const ids = await localIdentities()
```

## develop

### start a local server

```sh
npm start
```

## test
Run some automated tests of the cryptography API, not `webauthn`.

### start tests & watch for file changes

```sh
npm test
```

### run tests and exit

```sh
npm run test:ci
```

## see also

* [Passkey vs. WebAuthn: What's the Difference?](https://teampassword.com/blog/passkey-vs-webauthn)
* [Discoverable credentials deep dive](https://web.dev/articles/webauthn-discoverable-credentials)
* [Sign in with a passkey through form autofill](https://web.dev/articles/passkey-form-autofill)
* [an opinionated, “quick-start” guide to using passkeys](https://www.imperialviolet.org/2022/09/22/passkeys.html)

### [What's the WebAuthn User Handle (`response.userHandle`)?](https://www.corbado.com/blog/webauthn-user-id-userhandle#webauthn-user-handle)

> Its primary function is to enable the authenticator to map a set of credentials (passkeys) to a specific user account.

> A secondary use of the User Handle (response.userHandle) is to allow authenticators to know when to replace an existing resident key (discoverable credential) with a new one during the registration ceremony.

### `libsodium` docs

* [How can I sign and encrypt using the same key pair?](https://libsodium.gitbook.io/doc/quickstart#how-can-i-sign-and-encrypt-using-the-same-key-pair)



## credits

This is heavily influenced by [@lo-fi/local-data-lock](https://github.com/mylofi/local-data-lock) and [@lo-fi/webauthn-local-client](https://github.com/mylofi/webauthn-local-client). Thanks [@lo-fi organization](https://github.com/mylofi/local-data-lock) and [@getify](https://github.com/getify) for working in open source; this would not have been possible otherwise.
