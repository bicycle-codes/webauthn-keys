import { test, expect } from 'vitest'
import { deriveLockKey, signData } from '.'

let key
test('create some keys', async () => {
    key = await deriveLockKey()
    expect(key).toBeTruthy()
})

test('sign something', async () => {
    const sig = await signData('hello world', key)
    expect(sig).to.be.a('string')
    expect(sig.length).to.equal(88)
})
