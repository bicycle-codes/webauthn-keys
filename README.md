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
> [We only need 1 keypair](https://libsodium.gitbook.io/doc/quickstart#how-can-i-sign-and-encrypt-using-the-same-key-pair) for both signing and encrypting.

## Use
This exposes ESM and common JS via [package.json `exports` field](https://nodejs.org/api/packages.html#exports).

### ESM
```js
import {
    create,
    getKeys,
    encrypt,
    decrypt
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

### Common JS
```js
const keys = require('@bicycle-codes/webauthn-keys')
```

## Example

### JS
```js
import '@bicycle-codes/webauthn-keys'
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
<script type="module" src="./webauth-keys.min.js"></script>
```

## see also

* [Passkey vs. WebAuthn: What's the Difference?](https://teampassword.com/blog/passkey-vs-webauthn)

### `libsodium` docs

* [How can I sign and encrypt using the same key pair?](https://libsodium.gitbook.io/doc/quickstart#how-can-i-sign-and-encrypt-using-the-same-key-pair)
