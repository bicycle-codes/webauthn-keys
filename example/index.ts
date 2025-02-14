import { type FunctionComponent, render } from 'preact'
import { useCallback, useMemo, useRef } from 'preact/hooks'
import { useSignal, signal } from '@preact/signals'
import { html } from 'htm/preact'
import Debug from '@substrate-system/debug'
import type { AuthResponse, Identity, LockKey } from '../src/types'
import {
    toBase64String,
    create,
    localIdentities,
    pushLocalIdentity,
    getKeys,
    encrypt,
    decrypt,
    supportsWebAuthn,
    authDefaults,
    auth,
} from '../src/index.js'
import './style.css'
const debug = Debug()
const ABORT = 'abort'

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
    const input = useRef<HTMLInputElement>()

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
    useMemo(async () => {
        const ids = await localIdentities()
        if (!ids) return
        localIds.value = ids
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
        const id = await create({
            username,
            relyingPartyName: 'Example application'
        })
        await pushLocalIdentity(id.localID, id.record)
        const newState = { ...localIds.value, [id.localID]: id.record }
        localIds.value = newState
        myKeys.value = id.keys
        currentStep.value = 'logged-in'
    }, [])

    /**
     * This is when you click the "login as ..." button
     * @NOTE We need to abort the pending login that we use
     * for autocomplete.
     */
    const login = useCallback(async (ev:MouseEvent) => {
        ev.preventDefault()
        const localID = (ev.target as HTMLButtonElement).dataset.localId
        debug('login with this ID', localID)
        abortSignal.abort(ABORT + ' Login via app UI')
        const authResult = await auth()
        const keys = getKeys(authResult)
        myKeys.value = keys
        currentStep.value = 'logged-in'
    }, [])

    const encryptMsg = useCallback((ev:SubmitEvent) => {
        ev.preventDefault()
        if (!myKeys.value) throw new Error('not keys')
        const form = ev.target as HTMLFormElement
        const text = form.elements['text'].value
        debug('encrypting...', text.value)
        const encrypted = encrypt(text, myKeys.value)
        debug('the encrypted text', encrypted)
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

    /**
     * @NOTE
     * This doesn't get called if you use the autocomplete to login.
     */
    const loginViaInput = useCallback((ev:SubmitEvent) => {
        ev.preventDefault()
        debug('logging in via the input', ev)
    }, [])

    return html`<div class="webauthn-keys-demo">
        <h1>webauthn-keys demo</h1>

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
                    html`<div class="logged-in">
                        <h2>Your keys</h2>
                        <div class="keys">
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
                    <form onSubmit=${loginViaInput}>
                        <div>
                            <input
                                ref=${input}
                                type="text"
                                id="username"
                                name="username"
                                autocomplete="username webauthn"
                            />
                        </div>
                        <div>
                            <button type="submit">Login</button>
                        </div>
                    </form>

                    <form class="choose-your-path">
                        <div>
                            <button onClick=${() => (currentStep.value = 'create')}>
                                Create a new identity
                            </button>
                        </div>
                    </form>` :
                    null
                }
            </div> <!-- /.action -->

            <div class="right">
                ${!currentStep.value ?
                    html`
                        <h2>Existing identities</h2>
                        <p>
                            The key is the user's ID.
                        </p>
                        ${localIds.value ?
                            html`
                                <ul>
                                    ${Object.keys(localIds.value).map(k => {
                                        const id = localIds.value![k]

                                        return html`<li class="id">
                                            <pre><b>key: </b>${k}</pre>
                                            <pre>
                                                <b>value</b>:
                                                <br />
                                                ${JSON.stringify(id, (k, val) => {
                                                    if (k === 'spki' || k === 'raw') {
                                                        return toBase64String(val)
                                                    }
                                                    return val
                                                }, 2)}
                                            </pre>

                                            <p>
                                                <button onClick=${login} data-local-id=${k}>
                                                    Login as this user
                                                </button>
                                            </p>
                                        </li>`
                                    })}
                                </ul>
                            ` :
                            html`<em>none</em>`
                        }
                    ` :
                    html`<div class="the-message">
                        <h2>data<//>
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

render(html`<${Example} />`, document.getElementById('root')!)
