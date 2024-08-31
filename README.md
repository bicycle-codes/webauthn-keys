# webauthn keys
![tests](https://github.com/bicycle-codes/webauthn-keys/actions/workflows/nodejs.yml/badge.svg)
[![types](https://img.shields.io/npm/types/@bicycle-codes/webauthn-keys?style=flat-square)](README.md)
[![module](https://img.shields.io/badge/module-ESM%2FCJS-blue?style=flat-square)](README.md)
[![semantic versioning](https://img.shields.io/badge/semver-2.0.0-blue?logo=semver&style=flat-square)](https://semver.org/)
[![install size](https://packagephobia.com/badge?p=@bicycle-codes/webauthn-keys)](https://packagephobia.com/result?p=@bicycle-codes/webauthn-keys)
[![dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen.svg?style=flat-square)](package.json)
[![license](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat-square)](LICENSE)

A simple way to use crypto keys, protected by [webauthn](https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API) (biometric authentication).

We need a way to save a user ID, then access it iff the user authenticates via `webauthn`. A user ID is an ECC keypair.

We [save the `iv` of the our keypair](./src/index.ts#L46), which lets us re-create the same keypair on subsequent sessions.

> [!NOTE]  
> We are not using the [webcrypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) for creating keys, because we are waiting on ECC support in all browsers.

[See a live demo](https://bicycle-codes.github.io/webauthn-keys/)

<!-- toc -->

## install

```sh
npm i -S @bicycle-codes/webauthn-keys
```

## Use
This exposes ESM and common JS via [package.json `exports` field](https://nodejs.org/api/packages.html#exports).

### ESM
```js
import '@bicycle-codes/webauthn-keys'
```

### Common JS
```js
require('@namespace/webauthn-keys')
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

### `libsodium` docs

* [How can I sign and encrypt using the same key pair?](https://libsodium.gitbook.io/doc/quickstart#how-can-i-sign-and-encrypt-using-the-same-key-pair)
