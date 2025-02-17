# WIP

**[manage passkeys in chrome](chrome://settings/passkeys)**

-----------------

[See imperialviolet.org](https://www.imperialviolet.org/2022/09/22/passkeys.html)

> That pending promise must be set up by the site before the user focuses the username field and triggers autocomplete. (Just adding the webauthn tag doesn’t do anything if there’s not a pending promise for the browser to resolve.) 

## remove account

See [local-data-lock docs](https://github.com/mylofi/local-data-lock?tab=readme-ov-file#removing-a-local-account).

---------------

In `ldl.js`, line 339 -- the place where we set the `localIdentites`

## user flow

* [ ] Should narrow the list of available user IDs inside the modal browser UI.
      It should only show appropriate usernames.
* [ ] It should offer to autocomplete. See [demo app](https://vella.ai/auth/)

See [this demo app](https://github.com/mylofi/lofi.id/blob/main/pwa-demo/web/js/app.js). They are using **session storage**.

```js
const loginSession = window.sessionStorage.getItem("login-session")

if (loginSession) {
    const name = loginSession.profileName
} else {
    promptWelcome()  // line 61
    // shows a "sweet alert"
}
```

They save the profiles in `localStorage`.

```js
// on promptLogin, read the profiles

function readStoredProfiles() {
	return (
		JSON.parse(
			window.localStorage.getItem("profiles") ||
			"null"
		) ||
		{}
	);
}
```

## add a suffix to the public key
Show the type of key via string suffix.

```js
{
	author: '@IGrkmx/GjfzaOLNjTpdmmPWuTj5xeSv/2pCP+yUI8eo=.ed25519'
}
```

### + signatures
```js
{
	signature: 'LJUQXvR6SZ9lQS9uRtHxicXAQ==.sig.ed25519'
}
```

### + hashes

```js
{
	hash: '&my-hash.sha256'
}
```

## see also

### shared keys

* [sodium.crypto_kx_server_session_keys](https://libsodium.gitbook.io/doc/key_exchange#example-server-side)

* [sodium.crypto_kx_client_session_keys](https://libsodium.gitbook.io/doc/key_exchange#example-client-side)

