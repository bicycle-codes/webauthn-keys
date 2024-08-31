import { type FunctionComponent, render } from 'preact'
import { useCallback } from 'preact/hooks'
import { html } from 'htm/preact'
import './style.css'
import Debug from '@bicycle-codes/debug'
import {
    registerLocalIdentity,
    localIdentities,
} from '../src/index.js'
const debug = Debug()

debug('local ids', await localIdentities())

// @ts-expect-error dev
window.loadLocals = localIdentities

const Example:FunctionComponent<unknown> = function () {
    const register = useCallback(async (ev:SubmitEvent) => {
        ev.preventDefault()
        const form = ev.target as HTMLFormElement
        const els = form.elements
        const username = (els['username'] as HTMLInputElement).value
        debug('click', username)
        const id = await registerLocalIdentity(undefined, undefined, {
            username
        })
        debug('id', id)
    }, [])

    const storeThem = useCallback((ev:MouseEvent) => {
        ev.preventDefault()
    }, [])

    return html`<form onSubmit=${register}>
        <div>
            <input type="text" name="username" id="username" />
        </div>

        <div>
            <button type="submit">
                Register with webauthn
            </button>
        </div>

        <div>
            <button onClick=${storeThem}>store them</button>
        </div>
    </form>`
}

render(html`<${Example} />`, document.getElementById('root')!)
