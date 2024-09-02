import { test } from '@bicycle-codes/tapzero'
import { deriveLockKey } from '../dist/index.js'

test('derive a new key', async t => {
    const keys = await deriveLockKey()

    t.ok(keys.publicKey, 'should return a keypair')
})
