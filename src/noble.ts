import { webcrypto } from '@bicycle-codes/one-webcrypto'
import { secretbox } from '@noble/ciphers/salsa'
import { randomBytes } from '@noble/ciphers/webcrypto'
import { utf8ToBytes, bytesToUtf8 } from '@noble/ciphers/utils'
import { toString } from 'uint8arrays'
import type {
    Msg,
    PrivateKey,
    PublicKey,
    SymmKey,
    CharSize,
} from './types'
import Debug from '@bicycle-codes/debug'
const debug = Debug()

const key = randomBytes(32)
const nonce = randomBytes(24)
const box = secretbox(key, nonce)

const encrypted = box.seal(utf8ToBytes('hello, noble'))

debug('encrypted', toString(encrypted, 'base64pad'))

const decrypted = box.open(encrypted)

debug('decrypted', bytesToUtf8(decrypted))

/**
 * @see {@link https://github.com/paulmillr/noble-ciphers/discussions/32 Equivalent of Sodium's crypto_box_seal }
 * @see {@link https://github.com/dajiaji/hpke-js/tree/main/packages/dhkem-x25519 encrypt with noble}
 * The first one is via {@link https://github.com/paulmillr/noble-curves/discussions/123 noble discussion}
 *
 * @see {@link https://github.com/paulmillr/noble-curves/discussions/122 seeded ed25519 keys}
 *
 * @see {@link https://github.com/paulmillr/noble-ciphers/discussions/32#discussioncomment-8594278 As mentioned in the README, those are equivalent}
 */

export async function encrypt (
    msg:Msg,
    privateKey:PrivateKey,
    publicKey:string|PublicKey,
    charSize:CharSize = DEFAULT_CHAR_SIZE,
    curve:EccCurve = DEFAULT_ECC_CURVE,
    opts?:Partial<SymmKeyOpts>
):Promise<ArrayBuffer> {
    const importedPublicKey = typeof publicKey === 'string'
        ? await keys.importPublicKey(publicKey, curve, KeyUse.Exchange)
        : publicKey

    const cipherKey = await getSharedKey(privateKey, importedPublicKey, opts)
    return aes.encryptBytes(normalizeUnicodeToBuf(msg, charSize), cipherKey, opts)
}

export async function getSharedKey (
    privateKey:PrivateKey,
    publicKey:PublicKey,
    opts?:{ iv:ArrayBuffer }
):Promise<SymmKey> {
    return webcrypto.subtle.deriveKey(
        { name:ECC_EXCHANGE_ALG, public:publicKey },
        privateKey,
        {
            name: opts?.alg || DEFAULT_SYMM_ALG,
            length: opts?.length || DEFAULT_SYMM_LEN
        },
        false,
        ['encrypt', 'decrypt']
    )
}
