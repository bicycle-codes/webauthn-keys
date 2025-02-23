# webauthn keys
![tests](https://github.com/bicycle-codes/webauthn-keys/actions/workflows/nodejs.yml/badge.svg)
[![types](https://img.shields.io/npm/types/@bicycle-codes/webauthn-keys?style=flat-square)](README.md)
[![module](https://img.shields.io/badge/module-ESM-blue?style=flat-square)](README.md)
[![semantic versioning](https://img.shields.io/badge/semver-2.0.0-blue?logo=semver&style=flat-square)](https://semver.org/)
[![install size](https://flat.badgen.net/packagephobia/install/@bicycle-codes/webauthn-keys?cache-control=no-cache)](https://packagephobia.com/result?p=@bicycle-codes/webauthn-keys)
[![license](https://img.shields.io/badge/license-Polyform_Non_Commercial-26bc71?style=flat-square)](LICENSE)


A simple way to use crypto keys with [webauthn](https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API)
(biometric authentication).

Save an ECC keypair, then access it iff the user authenticates via `webauthn`.

[See a live demo](https://bicycle-codes.github.io/webauthn-keys/)

<details><summary><h2>Contents</h2></summary>

<!-- toc -->

- [install](#install)
- [how it works](#how-it-works)
- [get started](#get-started)
  * [first session](#first-session)
- [Use](#use)
  * [ESM](#esm)
  * [pre-built JS](#pre-built-js)
- [example](#example)
  * [Create a new keypair](#create-a-new-keypair)
  * [Save public data to `indexedDB`](#save-public-data-to-indexeddb)
  * [get a persisted keypair](#get-a-persisted-keypair)
  * [See also](#see-also)
- [develop](#develop)
  * [start a local server](#start-a-local-server)
- [API](#api)
  * [`create`](#create)
  * [`auth`](#auth)
  * [`pushLocalIdentity`](#pushlocalidentity)
  * [`getKeys`](#getkeys)
  * [`stringify`](#stringify)
  * [`signData`](#signdata)
  * [`verify`](#verify)
  * [`encrypt`](#encrypt)
  * [`decrypt`](#decrypt)
  * [`localIdentities`](#localidentities)
- [test](#test)
  * [start tests & watch for file changes](#start-tests--watch-for-file-changes)
  * [run tests and exit](#run-tests-and-exit)
- [see also](#see-also)
  * [What's the WebAuthn User Handle (`response.userHandle`)?](#whats-the-webauthn-user-handle-responseuserhandle)
  * [`libsodium` docs](#libsodium-docs)
- [credits](#credits)

<!-- tocstop -->

</details>

## install

```sh
npm i -S @bicycle-codes/webauthn-keys
```

## how it works

We [save the `iv` of the our keypair](./src/index.ts#L80), which lets us
[re-create the same keypair](https://libsodium.gitbook.io/doc/public-key_cryptography/public-key_signatures#key-pair-generation)
on subsequent sessions.

The secret `iv` is set in the `user.id` property in a
[PublicKeyCredentialCreationOptions](https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialCreationOptions)
object. The browser saves the credential, and will only read it after
successful authentication with the `webauthn` API.

> [!NOTE]
> We are not using the [webcrypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
> for creating keys, because we are waiting on ECC support in all browsers.

> [!NOTE]
> [We only need 1 keypair](https://libsodium.gitbook.io/doc/quickstart#how-can-i-sign-and-encrypt-using-the-same-key-pair)
> for both signing and encrypting. Internally, we create 2 keypairs -- one
> for signing and one for encryption -- but this is hidden from the interface.

## get started

### first session

Create a new keypair.

```js
import { create } from '@bicycle-codes/webauthn-keys'

const id = await create({  // create a new user
    username: 'alice'
})
```

Save the new user to `indexedDB`

```js
import { pushLocalIdentity } from '@bicycle-codes/webauthn-keys'

await pushLocalIdentity(id.localID, id.record)
```

Login with this user

```js
import { auth } from '@bicycle-codes/webauthn-keys'

// ... sometime in the future, login again ...

const localID = buttonElement.dataset.localId
const authResult = await auth(localID!)
```

------------------------------------------------------------------

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
    AuthResponse
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
Link to the file you copied.

```html
<script type="module" src="./webauthn-keys.min.js"></script>
```

------------------------------------------------------------------

## example

### Create a new keypair

Create a new keypair, and keep it secret with the `webatuhn` API.

```ts
import { create } from '@bicycle-codes/webauthn-keys'

const id = await create({
    username: 'alice',  // unique within relying party (this device)
    displayName: 'Alice Example',  // human-readable name
    relyingPartyName: 'Example application'  // rp.name. Default is domain name
})
```

### Save public data to `indexedDB`

Save the public data of the new ID to `indexedDB`:

```ts
import { pushLocalIdentity } from '@bicycle-codes/webauthn-keys'

// save to indexedDB
await pushLocalIdentity(id.localID, id.record)
```

### get a persisted keypair

Login again, and get the same keypair in memory. This will prompt for biometric authentication.

```ts
import { auth, getKeys } from '@bicycle-codes/webauthn-keys'

const authResult = await auth()
const keys = getKeys(authResult)
```

### See also
* [username property](https://www.corbado.com/blog/webauthn-user-id-userhandle#webauthn-user-name)
* [displayName property](https://www.corbado.com/blog/webauthn-user-id-userhandle#webauthn-user-display-name)
* [What's the Difference Between User Name and User Display Name?](https://www.corbado.com/blog/webauthn-user-id-userhandle#user-name-vs-user-display-name)


-------------------------------------------------------------------------

## develop

>
> [!TIP]
> You can use the browser dev tools to [setup a virtual authenticator](https://developer.chrome.com/docs/devtools/webauthn)
>

### start a local server

```sh
npm start
```

-------------------------------------------------------------------

## API

### `create`
Create a new keypair. The relying party ID defaults to the current `location.hostname`.

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
await pushLocalIdentity(id.localID, record)
```

### `auth`
Prompt the user for authentication with `webauthn`.

```ts
async function auth (
    opts:Partial<CredentialRequestOptions> = {}
):Promise<PublicKeyCredential & { response:AuthenticatorAssertionResponse }>
```

#### `auth` example

```ts
import { auth, getKeys } from '@bicycle-codes/webauthn'

const authResult = await auth()
const keys = getKeys(authResult)
```

### `pushLocalIdentity`
Take the `localId` created by the `create` call, and save it to `indexedDB`.

```ts
async function pushLocalIdentity (localId:string, id:Identity):Promise<void>
```

#### `pushLocalIdentity` example
```ts
const id = await create({
    username,
    relyingPartyName: 'Example application'
})
await pushLocalIdentity(id.localID, id.record)
```


### `getKeys`
Authenticate with a saved identity; takes the response from `auth()`.

```ts
function getKeys (opts:(PublicKeyCredential & {
    response:AuthenticatorAssertionResponse
})):LockKey
```

#### `getKeys` example

```ts
import { getKeys, auth } from '@bicycle-codes/webauthn-keys'

// authenticate
const authData = await auth()

// get keys from auth response
const keys = getKeys(authData)
```

### `stringify`
Return a `base64` encoded string of the given public key.

```ts
function stringify (keys:LockKey):string
```

#### `stringify` example
```ts
import { stringify } from '@bicycle-codes/webauthn-keys'

const keyString = stringify(myKeys)
// => 'welOX9O96R6WH0S8cqqwMlPAJ3VwMgAZEnc1wa1MN70='
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

### `verify`
Check that the given signature is valid with the given data.

```ts
export async function verify (
    data:string|Uint8Array,
    sig:string|Uint8Array,
    keys:{ publicKey:Uint8Array|string }
):Promise<boolean>
```

#### `verify` example
```ts
import { verify } from '@bicycle-codes/webauthn-keys'

const isOk = await verify('hello', 'dxKmG3oTEN2i23N9d...', {
    publicKey: '...'  // Uint8Array or string
})
// => true
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


-----------------------------------------------------------------------


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


--------------------------------------------------------------------------


## see also

* [Passkey vs. WebAuthn: What's the Difference?](https://teampassword.com/blog/passkey-vs-webauthn)
* [Discoverable credentials deep dive](https://web.dev/articles/webauthn-discoverable-credentials)
* [Sign in with a passkey through form autofill](https://web.dev/articles/passkey-form-autofill)
* [an opinionated, “quick-start” guide to using passkeys](https://www.imperialviolet.org/2022/09/22/passkeys.html)

### [What's the WebAuthn User Handle (`response.userHandle`)?](https://www.corbado.com/blog/webauthn-user-id-userhandle#webauthn-user-handle)

> Its primary function is to enable the authenticator to map a set of
> credentials (passkeys) to a specific user account.

> A secondary use of the User Handle (response.userHandle) is to allow
> authenticators to know when to replace an existing resident key (discoverable
> credential) with a new one during the registration ceremony.

### `libsodium` docs

* [How can I sign and encrypt using the same key pair?](https://libsodium.gitbook.io/doc/quickstart#how-can-i-sign-and-encrypt-using-the-same-key-pair)


------------------------------------------------------------------------


## credits

This is heavily influenced by [@lo-fi/local-data-lock](https://github.com/mylofi/local-data-lock)
and [@lo-fi/webauthn-local-client](https://github.com/mylofi/webauthn-local-client).
Thanks [@lo-fi organization](https://github.com/mylofi/local-data-lock) and
[@getify](https://github.com/getify) for working in open source; this would not
have been possible otherwise.
