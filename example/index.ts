import { type FunctionComponent, render } from 'preact'
import { useCallback, useEffect } from 'preact/hooks'
import { useSignal, signal, batch } from '@preact/signals'
import { html } from 'htm/preact'
import Debug from '@substrate-system/debug'
import { NBSP } from '@substrate-system/util/CONSTANTS'
import '@substrate-system/css-normalize'
import type { AuthResponse, Identity, LockKey } from '../src/types'
import {
    toBase64String,
    create,
    listLocalIdentities,
    pushLocalIdentity,
    getKeys,
    encrypt,
    decrypt,
    supportsWebAuthn,
    authDefaults,
    removeLocalAccounts,
    auth,
} from '../src/index.js'
import './style.css'
const debug = Debug()
const ABORT = 'abort'

// @ts-expect-error dev
window.localIds = listLocalIdentities

// we don't have an equivalent to "unlock account", as in the data-lock example
// (https://mylofi.github.io/local-data-lock/)
// how are they populating the select box?
//
// selectEl.appendChild(localAcctID)
//   localAcctID comes from `listLocalIdentites`

// selectedAcctEl.change => changeSelectedAcct
// this just disables/enables the 'unlock acct' button

// unlock acct btn.click => unlockAcct
//   getLockKey(selectedAcct)

//
// pass displayname to register
// register is imported from local-client
//

// https://github.com/mylofi/webauthn-local-client/blob/main/test/test.js
// registerBtn.onClick => promptRegister(false) => registerCredential(name, idString)
//   id = toUint8(userId)
//
// reRegisterBtn.onClick => promptRegister(false)
// authBtn.onClick => promptAuth
// '#registered-credentials'.onClick => onAuthCredential

// resetAllAccountsButton.click => resetAllAccounts
// localIds.forEach => removeLocalAccount(id)

// sodium.from_string  <-- Uint8Array from string

// -------------------------------

/*
This is like a logout function.

async function lockAccount() {
    clearLockKeyCache(currentAccountID);
    currentAccountID = null;
    selectAccountEl.selectedIndex = 0;
    changeSelectedAccount();
    updateElements();
    showToast("Account locked.");
}
*/

//
// it ends up at `clearLockKeyCache`
//

//
// How to login with an ID, not with the OS passkey selector?
//

const currentStep = signal<'create'|'logged-in'|null>(null)
const myKeys = signal<LockKey|null>(null)
const abortSignal = new AbortController();

(async function () {
    if (!(await supportsWebAuthn())) {
        return debug('no support')
    }

    const opts = authDefaults({
        signal: abortSignal.signal,
    }, {
        userVerification: 'required'
    })

    //
    // Need to do this for the autocomplete to work.
    // There must be a pending promise to `navigator.credentials.get` in
    // order for the autocomplete credentials to show.
    // See https://www.imperialviolet.org/2022/09/22/passkeys.html
    //
    try {
        const creds = await navigator.credentials.get(opts) as AuthResponse
        const keys = getKeys(creds)
        myKeys.value = keys
        currentStep.value = 'logged-in'
    } catch (err) {
        if (String(err as TypeError).includes(ABORT)) return
        debug('failure...', err)
        throw err
    }
})()

const Example:FunctionComponent = function () {
    const localIds = useSignal<Record<string, Identity>|null>(null)
    const encryptedText = useSignal<string|null>(null)
    const decryptedText = useSignal<string|null>(null)
    const loggedInAs = useSignal<null|Identity>(null)

    if (import.meta.env.DEV) {
        // @ts-expect-error dev
        window.state = {
            myKeys,
            encryptedText
        }
    }

    /**
     * For the list of local IDs on the right hand side
     */
    useEffect(() => {
        (async () => {
            const ids = await listLocalIdentities()
            if (!ids) return
            localIds.value = ids
        })()
    }, [])

    /**
     * Create a new ID and keypair
     */
    const register = useCallback(async (ev:SubmitEvent) => {
        ev.preventDefault()
        abortSignal.abort(ABORT + ' -- registering as a new user')
        const form = ev.target as HTMLFormElement
        const els = form.elements
        const username = (els['username'] as HTMLInputElement).value
        const id = await create({  // create a new user
            username
        })
        // save the user to `indexedDB`
        await pushLocalIdentity(id.localID, id.record)
        const newState = { ...localIds.value, [id.localID]: id.record }
        batch(() => {
            localIds.value = newState
            myKeys.value = id.keys
            loggedInAs.value = id.record
            currentStep.value = 'logged-in'
        })
    }, [])

    /**
     * This is when you click the "login as this user" button
     * @NOTE We need to abort the pending login that we use
     * for autocomplete.
     */
    const login = useCallback(async (ev:MouseEvent) => {
        ev.preventDefault()
        const localID = (ev.target as HTMLButtonElement).dataset.localId
        debug('login with this ID', localID)
        abortSignal.abort(ABORT + ' Login via app UI')
        const authResult = await auth(localID!)
        debug('the auth response', authResult)
        const keys = getKeys(authResult)
        // get the username from indexedDB
        const record = localIds.value![localID!]
        debug('the record', record)

        batch(() => {
            loggedInAs.value = record
            myKeys.value = keys
            currentStep.value = 'logged-in'
        })
    }, [])

    const encryptMsg = useCallback((ev:SubmitEvent) => {
        ev.preventDefault()
        if (!myKeys.value) throw new Error('not keys')
        const form = ev.target as HTMLFormElement
        const text = form.elements['text'].value
        const encrypted = encrypt(text, myKeys.value)
        encryptedText.value = encrypted
    }, [])

    const decryptMsg = useCallback((ev:MouseEvent) => {
        ev.preventDefault()
        if (!myKeys.value) throw new Error('not keys')
        const msg = encryptedText.value!
        const decrypted = decrypt(msg, myKeys.value, {
            parseJSON: false
        })

        decryptedText.value = decrypted
    }, [])

    const removeIds = useCallback(async (ev:MouseEvent) => {
        ev.preventDefault()
        if (!localIds.value) {
            debug('nothing to remove...', localIds.value)
            return
        }

        debug('removing them...', localIds.value)

        await removeLocalAccounts(Object.keys(localIds.value))
        localIds.value = null
    }, [])

    return html`<div class="webauthn-keys-demo">
        <h1>webauthn-keys demo</h1>

        <!-- <section class="explanation">
            <p>
            </p>
        </section> -->

        <section class="main">
            <div class="action">
                ${currentStep.value === 'create' ?
                    html`
                        <h2>Create a new identity</h2>
                        <form class="register" onSubmit=${register}>
                            <div>
                                <label>
                                    Username
                                    <input
                                        type="text"
                                        id="username"
                                        name="username"
                                        autocomplete="username webauthn"
                                    />
                                </label>
                            </div>

                            <div>
                                <button type="submit">
                                    Register with webauthn
                                </button>
                            </div>
                        </form>
                    ` :
                    null
                }

                ${currentStep.value === 'logged-in' ?
                    html`
                    <p>
                        You are logged in. Refresh the page to login again.
                    </p>

                    <div class="logged-in">
                        <h2>Your keys</h2>
                        <div class="keys">
                            <p>
                                You are logged in as <strong>
                                    ${loggedInAs.value?.displayName}
                                </strong>.
                            </p>

                            <pre>
                                ${JSON.stringify(myKeys.value, (k, val) => {
                                    if (
                                        k === 'iv' ||
                                        k === 'publicKey' ||
                                        k === 'privateKey' ||
                                        k === 'encPK' ||
                                        k === 'encSK'
                                    ) {
                                        return toBase64String(val)
                                    }

                                    return val
                                }, 2)}
                            </pre>
                        </div>

                        <h2>Encrypt a message</h2>
                        <form onSubmit=${encryptMsg}>
                            <label for="text">
                                Your message
                            <//>
                            <textarea
                                name="text"
                                placeholder="Message here"
                                id="text"
                            ><//>

                            <button type="submit">Encrypt<//>
                        </form>
                    </div>` :
                    null
                }

                ${currentStep.value === null ?
                    html`<h2>Login</h2>
                    <div class="choose-your-path">
                        <div>
                            <button onClick=${() => (currentStep.value = 'create')}>
                                Create a new identity
                            </button>
                        </div>
                    </div>

                    <hr />

                    <div>
                        <p>
                            This will delete everything from${NBSP}
                            <code>indexedDB</code>.
                        </p>
                        <button onClick=${removeIds}>
                            Clear all IDs
                        </button>
                    </div>
                    ` :
                    null
                }
            </div> <!-- /.action -->

            <div class="right">
                ${!currentStep.value ?
                    html`
                        <h2>Existing identities</h2>
                        ${localIds.value ?
                            html`
                                <ul>
                                    ${Object.keys(localIds.value).map(k => {
                                        const id = localIds.value![k]

                                        return html`<li class="id">
                                            <b>key: </b>
                                            <pre class="key">${k}</pre>
                                            <br />
                                            <b class="value">value:</b>
                                            <details>
                                                <pre>
                                                    ${JSON.stringify(
                                                        id,
                                                        idStringifier,
                                                        2)}
                                                </pre>
                                            </details>

                                            <div>
                                                <button
                                                    onClick=${login}
                                                    data-local-id=${k}
                                                >
                                                    Login as this user
                                                </button>
                                            </div>
                                        </li>`
                                    })}
                                </ul>
                            ` :
                            html`<em>none</em>`
                        }
                    ` :
                    html`<div class="the-message">
                        <h2>data</h2>
                        ${encryptedText.value ?
                            html`<div class="encrypted-text">
                                <h2>The encrypted text<//>
                                <p>${encryptedText}<//>
                            <//>
                            <div class="controls">
                                <button onClick=${decryptMsg}>Decrypt</button>
                            <//>` :
                            html`<em>none</em>`
                        }

                        ${decryptedText.value ?
                            html`<div class="decrypted-text">
                                <h2>The decrypted text<//>
                                <p>${decryptedText}</p>
                            </div>` :
                            null
                        }
                    <//>`
                }
            </div>
        </section>
    </div>`
}

function idStringifier (k:string, val:Uint8Array):string|Uint8Array {
    if (k === 'spki' || k === 'raw') {
        return toBase64String(val)
    }
    return val
}

render(html`<${Example} />`, document.getElementById('root')!)
