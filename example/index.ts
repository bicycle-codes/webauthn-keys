import { type FunctionComponent, render } from 'preact'
import { useCallback, useMemo } from 'preact/hooks'
import { useSignal } from '@preact/signals'
import { html } from 'htm/preact'
import Debug from '@bicycle-codes/debug'
import { toString } from 'uint8arrays'
import type { Identity, LockKey } from '../src/types'
import {
    create,
    localIdentities,
    pushLocalIdentity,
    getKeys,
    encrypt
} from '../src/index.js'
import './style.css'
const debug = Debug()

debug('local ids', await localIdentities())

// @ts-expect-error dev
window.loadLocals = localIdentities

const Example:FunctionComponent = function () {
    const currentStep = useSignal<'create'|'logged-in'|null>(null)
    const localIds = useSignal<Record<string, Identity>|null>(null)
    const myKeys = useSignal<LockKey|null>(null)

    useMemo(async () => {
        const ids = await localIdentities()
        if (!ids) return
        localIds.value = ids
    }, [])

    const register = useCallback(async (ev:SubmitEvent) => {
        ev.preventDefault()
        const form = ev.target as HTMLFormElement
        const els = form.elements
        const username = (els['username'] as HTMLInputElement).value
        debug('click', username)
        const id = await create(undefined, {
            username
        })
        debug('id', id)
        await pushLocalIdentity(id.localID, id.record)
        const newState = { ...localIds.value, [id.localID]: id.record }
        localIds.value = newState
    }, [])

    const login = useCallback(async (ev:MouseEvent) => {
        ev.preventDefault()
        const localID = (ev.target as HTMLButtonElement).dataset.localId
        debug('login with this ID', localID)
        const { record, keys } = await getKeys(localID!)
        debug('user record', record)
        debug('these are the keys', keys)
        myKeys.value = keys
        currentStep.value = 'logged-in'
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
                                    <input type="text" name="username" id="username" />
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
                                        // return val.slice(0, 6)
                                        return toString(val, 'base64')
                                    }

                                    return val
                                }, 2)}
                            </pre>
                        </div>

                        <form>
                            <h2>Encrypt a message</h2>
                            <form>
                                <textarea
                                    name="text"
                                    placeholder="Message here"
                                    id="text"
                                ><//>
                            </form>
                        </form>
                    </div>` :
                    null
                }

                ${currentStep.value === null ?
                    html`<form class="choose-your-path">
                        <div>
                            <button onClick=${() => (currentStep.value = 'create')}>
                                Create a new identity
                            </button>
                        </div>
                    </form>` :
                    null
                }
            </div> <!-- /.action -->

            <div class="saved">
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
                                            if (k === 'spki') {
                                                return val.slice(0, 6)
                                            }

                                            if (k === 'raw') {
                                                return val.slice(0, 6)
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
            </div>
        </section>
    </div>`
}

render(html`<${Example} />`, document.getElementById('root')!)
