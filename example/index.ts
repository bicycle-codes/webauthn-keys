import { type FunctionComponent, render } from 'preact'
import { useCallback, useState, useMemo } from 'preact/hooks'
import { html } from 'htm/preact'
import './style.css'
import Debug from '@bicycle-codes/debug'
import type { Identity } from '../src/types'
import {
    create,
    localIdentities,
    pushLocalIdentity,
    getKeys,
    // encrypt
} from '../src/index.js'
const debug = Debug()

debug('local ids', await localIdentities())

// @ts-expect-error dev
window.loadLocals = localIdentities

const Example:FunctionComponent = function () {
    const [step, setStep] = useState<'create'|'login'|null>(null)
    const [localIds, setLocalIds] = useState<Record<string, Identity>|null>(null)

    useMemo(async () => {
        const ids = await localIdentities()
        if (!ids) return
        setLocalIds(ids)
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
        const newState = { ...localIds, [id.localID]: id.record }
        setLocalIds(newState)
    }, [])

    const login = useCallback(async (ev:MouseEvent) => {
        ev.preventDefault()
        const localID = (ev.target as HTMLButtonElement).dataset.localId
        debug('login with this ID', localID)
        const { record, keys } = await getKeys(localID!)
        debug('user record', record)
        debug('key', keys)
    }, [])

    return html`<div class="webauthn-keys-demo">
        <h1>webauthn-keys demo</h1>

        <section class="main">
            <div class="action">
                ${step === 'create' ?
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

                ${step === 'login' ?
                    html`<h2>Login</h2>
                        <form>
                        </form>
                    ` :
                    null
                }

                ${step === null ?
                    html`<form class="choose-your-path">
                        <div>
                            <button onClick=${() => setStep('create')}>
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
                ${localIds ?
                    html`
                        <ul>
                            ${Object.keys(localIds).map(k => {
                                const id = localIds[k]

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
