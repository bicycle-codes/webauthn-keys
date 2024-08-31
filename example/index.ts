import { type FunctionComponent, render } from 'preact'
import { useCallback } from 'preact/hooks'
import { html } from 'htm/preact'
import './style.css'
import Debug from '@bicycle-codes/debug'
import { registerLocalIdentity } from '../src/index.js'
const debug = Debug()

const Example:FunctionComponent<unknown> = function () {
    const register = useCallback((ev:MouseEvent) => {
        ev.preventDefault()
        debug('click')
        registerLocalIdentity()
    }, [])

    return html`<div>
        <button onClick=${register}>
            Register with webauthn
        </button>
    </div>`
}

// const id = await registerLocalIdentity()
// debug('id', id)

document.addEventListener('DOMContentLoaded', () => {
    render(html`<${Example} />`, document.getElementById('root')!)
})

