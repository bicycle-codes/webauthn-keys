import { test, expect, describe } from 'vitest'
import {
    deriveLockKey,
    signData,
    verify,
    encrypt,
    decrypt,
    stringify
} from './index.js'
import type { LockKey } from './types.js'

describe('webauthn-keys', () => {
    let key:LockKey
    test('create some keys', async () => {
        key = await deriveLockKey()
        expect(key).toBeTruthy()
        expect(key.keyFormatVersion).toEqual(1)
    })

    let keyString:string
    test('serialize the public key', () => {
        keyString = stringify(key)
        expect(keyString).to.be.toBeTypeOf('string')
    })

    let sig:string
    test('sign something', async () => {
        sig = await signData('hello world', key)
        expect(sig).to.be.a('string')
        expect(sig.length).to.equal(88)
    })

    test('verify a signature', async () => {
        const isOk = await verify('hello world', sig, key)
        expect(isOk).toEqual(true)
    })

    test('verify a signature given a string public key', async () => {
        const isOk = await verify('hello world', sig, {
            publicKey: keyString
        })
        expect(isOk).toEqual(true)
    })

    test('verify an invalid signature', async () => {
        const badSig = 'abc' + sig.slice(-3)
        const isOk = await verify('hello world', badSig, key)
        expect(isOk).toEqual(false)
    })

    let encrypted:string
    test('encrypt something', async () => {
        encrypted = encrypt('hello encryption', key)
        expect(encrypted).to.be.a('string')
    })

    test('decrypt the string', async () => {
        const decrypted = decrypt(encrypted, key, { parseJSON: false })
        expect(decrypted).to.equal('hello encryption')
    })
})
