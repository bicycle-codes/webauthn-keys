import { test, expect, describe } from 'vitest'
import { deriveLockKey, signData, verify, encrypt, decrypt } from '.'

describe('webauthn-keys', () => {
    let key
    test('create some keys', async () => {
        key = await deriveLockKey()
        expect(key).toBeTruthy()
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
