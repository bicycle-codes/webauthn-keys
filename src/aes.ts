import { webcrypto } from '@bicycle-codes/one-webcrypto'
import * as utils from './util.js'
import { DEFAULT_SYMM_ALG } from './constants.js'
import type { SymmKey, CipherText, Msg } from './types.js'
import uint8arrays from 'uint8arrays'

export async function encryptBytes (
    msg:Msg,
    key:SymmKey|string,
): Promise<CipherText> {
    const data = utils.normalizeUtf16ToBuf(msg)
    const importedKey = typeof key === 'string' ?
        await keys.importKey(key, opts) :
        key
    const iv = utils.randomBuf(12)
    const cipherBuf = await webcrypto.subtle.encrypt(
        {
            name: 'AES-GCM',
            // AES-CTR uses a counter, AES-GCM/AES-CBC use an initialization vector
            iv,
        },
        importedKey,
        data
    )

    return utils.joinBufs(iv, cipherBuf)
}

export async function decryptBytes (
    msg: Msg,
    key: SymmKey | string,
    opts?: Partial<SymmKeyOpts>
): Promise<ArrayBuffer> {
    const cipherText = utils.normalizeBase64ToBuf(msg)
    const importedKey = typeof key === 'string' ? await keys.importKey(key, opts) : key
    const alg = opts?.alg || DEFAULT_SYMM_ALG
    const iv = cipherText.slice(0, 16)
    const cipherBytes = cipherText.slice(16)
    const msgBuff = await webcrypto.subtle.decrypt(
        {
            name: alg,
            // AES-CTR uses a counter, AES-GCM/AES-CBC use an initialization vector
            iv: alg === SymmAlg.AES_CTR ? undefined : iv,
            counter: alg === SymmAlg.AES_CTR ? new Uint8Array(iv) : undefined,
            length: alg === SymmAlg.AES_CTR ? DEFAULT_CTR_LEN : undefined,
        },
        importedKey,
        cipherBytes
    )
    return msgBuff
}

export async function encrypt (
    msg: Msg,
    key: SymmKey | string,
    opts?: Partial<SymmKeyOpts>
): Promise<string> {
    const cipherText = await encryptBytes(msg, key, opts)
    return utils.arrBufToBase64(cipherText)
}

export async function decrypt (
    msg: Msg,
    key: SymmKey | string,
    opts?: Partial<SymmKeyOpts>
): Promise<string> {
    const msgBytes = await decryptBytes(msg, key, opts)
    return utils.arrBufToStr(msgBytes, 16)
}

export async function exportKey (key: SymmKey): Promise<string> {
    const raw = await webcrypto.subtle.exportKey('raw', key)
    return utils.arrBufToBase64(raw)
}

export default {
    encryptBytes,
    decryptBytes,
    encrypt,
    decrypt,
    exportKey
}

async function importKey (
    base64key:string,
    opts?:Partial<SymmKeyOpts>
):Promise<SymmKey> {
    const buf = utils.base64ToArrBuf(base64key)
    return webcrypto.subtle.importKey(
        'raw',
        buf,
        {
            name: opts?.alg || DEFAULT_SYMM_ALG,
            length: opts?.length || DEFAULT_SYMM_LEN,
        },
        true,
        ['encrypt', 'decrypt']
    )
}

export function arrBufToBase64 (buf:ArrayBuffer):string {
    return uint8arrays.toString(new Uint8Array(buf), 'base64pad')
}
